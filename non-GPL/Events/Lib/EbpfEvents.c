// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#include "EbpfEvents.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/resource.h>
#include <sys/utsname.h>
#include <unistd.h>

#include "EventProbe.skel.h"

#define KERNEL_VERSION(maj, min, patch)                                                            \
    (((maj) << 16) | ((min) << 8) | (patch > 255 ? 255 : (patch)))

bool log_verbose = false;
static int verbose(const char *fmt, ...);

struct ring_buf_cb_ctx {
    ebpf_event_handler_fn cb;
    uint64_t events_mask;
};

struct ebpf_event_ctx {
    uint64_t features;
    struct ring_buffer *ringbuf;
    struct EventProbe_bpf *probe;
    struct ring_buf_cb_ctx *cb_ctx;
};

/* This is just a thin wrapper that calls the event context's saved callback */
static int ring_buf_cb(void *ctx, void *data, size_t size)
{
    struct ring_buf_cb_ctx *cb_ctx = ctx;
    if (cb_ctx == NULL) {
        return 0;
    }
    ebpf_event_handler_fn cb = cb_ctx->cb;
    if (cb == NULL) {
        return 0;
    }
    struct ebpf_event_header *evt = data;
    if (evt == NULL) {
        return 0;
    }
    if (evt->type & cb_ctx->events_mask) {
        return cb(evt);
    }
    return 0;
}

const struct btf_type *resolve_btf_type_by_func(struct btf *btf, const char *func)
{
    if (func == NULL) {
        goto out;
    }

    for (int i = 0; i < btf__type_cnt(btf); i++) {
        int btf_type = btf__resolve_type(btf, i);
        if (btf_type < 0)
            continue;

        const struct btf_type *btf_type_ptr = btf__type_by_id(btf, btf_type);

        if (!btf_is_func(btf_type_ptr))
            continue;

        const char *name = btf__name_by_offset(btf, btf_type_ptr->name_off);
        if (name == NULL)
            continue;
        if (strcmp(name, func))
            continue;

        int proto_btf_type = btf__resolve_type(btf, btf_type_ptr->type);
        if (proto_btf_type < 0)
            goto out;

        const struct btf_type *proto_btf_type_ptr = btf__type_by_id(btf, proto_btf_type);
        if (!btf_is_func_proto(proto_btf_type_ptr))
            continue;

        return proto_btf_type_ptr;
    }

out:
    return NULL;
}

/* Find the BTF type relocation index for a named argument of a kernel function */
static int resolve_btf_func_arg_idx(struct btf *btf, const char *func, const char *arg)
{
    int ret = -1;

    const struct btf_type *proto_btf_type_ptr = resolve_btf_type_by_func(btf, func);
    if (!proto_btf_type_ptr)
        goto out;
    if (!arg)
        goto out;

    struct btf_param *params = btf_params(proto_btf_type_ptr);
    for (int j = 0; j < btf_vlen(proto_btf_type_ptr); j++) {
        const char *cur_name = btf__name_by_offset(btf, params[j].name_off);
        if (cur_name == NULL) {
            continue;
        }
        if (strcmp(cur_name, arg) == 0) {
            ret = j;
            goto out;
        }
    }

out:
    return ret;
}

/* Find the BTF relocation index for a func return value */
static int resolve_btf_func_ret_idx(struct btf *btf, const char *func)
{
    int ret                                   = -1;
    const struct btf_type *proto_btf_type_ptr = resolve_btf_type_by_func(btf, func);
    if (!proto_btf_type_ptr)
        goto out;

    ret = btf_vlen(proto_btf_type_ptr);

out:
    return ret;
}

/* Given a function name and an argument name, returns the argument index
 * in the function signature.
 */
#define FILL_FUNC_ARG_IDX(obj, btf, func, arg)                                                     \
    ({                                                                                             \
        int __r = -1;                                                                              \
        int r   = resolve_btf_func_arg_idx(btf, #func, #arg);                                      \
        if (r >= 0)                                                                                \
            __r = 0;                                                                               \
        obj->rodata->arg__##func##__##arg##__ = r;                                                 \
        __r;                                                                                       \
    })

/* Given a function name, returns the "ret" argument index. */
#define FILL_FUNC_RET_IDX(obj, btf, func)                                                          \
    ({                                                                                             \
        int __r = -1;                                                                              \
        int r   = resolve_btf_func_ret_idx(btf, #func);                                            \
        if (r >= 0)                                                                                \
            __r = 0;                                                                               \
        obj->rodata->ret__##func##__ = r;                                                          \
        __r;                                                                                       \
    })

/* Given a function name and an argument name, returns whether the argument
 * exists or not.
 */
#define FILL_FUNC_ARG_EXISTS(obj, btf, func, arg)                                                  \
    ({                                                                                             \
        int __r = -1;                                                                              \
        int r   = resolve_btf_func_arg_idx(btf, #func, #arg);                                      \
        if (r >= 0) {                                                                              \
            obj->rodata->exists__##func##__##arg##__ = true;                                       \
            __r                                      = 0;                                          \
        }                                                                                          \
        __r;                                                                                       \
    })

/* Given a function name, returns whether it exists in the provided BTF. */
#define BTF_FUNC_EXISTS(btf, func) ({ (bool)resolve_btf_type_by_func(btf, #func); })

/* Fill context relocations for kernel functions
 * You can add additional functions here by using the macros defined above.
 *
 * Rodata constants must be declared in `EventProbe.bpf.c` via the relative helper macros.
 */
static int probe_fill_relos(struct btf *btf, struct EventProbe_bpf *obj)
{
    int err = 0;

    err = err ?: FILL_FUNC_ARG_IDX(obj, btf, vfs_unlink, dentry);
    err = err ?: FILL_FUNC_RET_IDX(obj, btf, vfs_unlink);

    if (FILL_FUNC_ARG_EXISTS(obj, btf, vfs_rename, rd)) {
        /* We are on a 5.12- kernel */
        err = err ?: FILL_FUNC_ARG_IDX(obj, btf, vfs_rename, old_dentry);
        err = err ?: FILL_FUNC_ARG_IDX(obj, btf, vfs_rename, new_dentry);
    }
    err = err ?: FILL_FUNC_RET_IDX(obj, btf, vfs_rename);

    return err;
}

static int probe_resize_maps(struct EventProbe_bpf *obj)
{
    int ncpu = libbpf_num_possible_cpus();
    if (ncpu < 0) {
        verbose("could not determine number of CPUs: %d\n", ncpu);
        return ncpu;
    }

    int err = 0;
    if ((err = bpf_map__set_max_entries(obj->maps.event_buffer_map, ncpu)) < 0) {
        verbose("could not resize event buffer map: %d\n", err);
        return err;
    };

    return 0;
}

/* Some programs in the skeleton are mutually exclusive, based on local kernel features.
 */
static inline int probe_set_autoload(struct btf *btf, struct EventProbe_bpf *obj, uint64_t features)
{
    int err            = 0;
    bool has_bpf_tramp = features & EBPF_FEATURE_BPF_TRAMP;

    // do_renameat2 kprobe and fentry probe are mutually exclusive.
    // disable auto-loading of kprobe if `do_renameat2` exists in BTF and
    // if bpf trampolines are supported on the current arch, and vice-versa.
    if (has_bpf_tramp && BTF_FUNC_EXISTS(btf, do_renameat2)) {
        err = err ?: bpf_program__set_autoload(obj->progs.kprobe__do_renameat2, false);
    } else {
        err = err ?: bpf_program__set_autoload(obj->progs.fentry__do_renameat2, false);
    }

    // tcp_v6_connect kprobes and fexit probe are mutually exclusive.
    // disable auto-loading of kprobes if `tcp_v6_connect` exists in BTF and
    // if bpf trampolines are supported on the current arch, and vice-versa.
    if (has_bpf_tramp && BTF_FUNC_EXISTS(btf, tcp_v6_connect)) {
        err = err ?: bpf_program__set_autoload(obj->progs.kprobe__tcp_v6_connect, false);
        err = err ?: bpf_program__set_autoload(obj->progs.kretprobe__tcp_v6_connect, false);
    } else {
        err = err ?: bpf_program__set_autoload(obj->progs.fexit__tcp_v6_connect, false);
    }

    // tty_write BTF information is not available on all supported kernels due
    // to a pahole bug, see:
    // https://rhysre.net/how-an-obscure-arm64-link-option-broke-our-bpf-probe.html
    //
    // If BTF is not present we can't attach a fentry/ program to it, so
    // fallback to a kprobe.
    if (has_bpf_tramp && BTF_FUNC_EXISTS(btf, tty_write)) {
        err = err ?: bpf_program__set_autoload(obj->progs.kprobe__tty_write, false);
    } else {
        err = err ?: bpf_program__set_autoload(obj->progs.fentry__tty_write, false);
    }

    // bpf trampolines are only implemented for x86. disable auto-loading of all
    // fentry/fexit progs if EBPF_FEATURE_BPF_TRAMP is not in `features` and
    // enable the k[ret]probe counterpart.
    if (has_bpf_tramp) {
        err = err ?: bpf_program__set_autoload(obj->progs.kprobe__do_unlinkat, false);
        err = err ?: bpf_program__set_autoload(obj->progs.kprobe__mnt_want_write, false);
        err = err ?: bpf_program__set_autoload(obj->progs.kprobe__vfs_unlink, false);
        err = err ?: bpf_program__set_autoload(obj->progs.kretprobe__vfs_unlink, false);
        err = err ?: bpf_program__set_autoload(obj->progs.kretprobe__do_filp_open, false);
        err = err ?: bpf_program__set_autoload(obj->progs.kprobe__vfs_rename, false);
        err = err ?: bpf_program__set_autoload(obj->progs.kretprobe__vfs_rename, false);
        err = err ?: bpf_program__set_autoload(obj->progs.kprobe__taskstats_exit, false);
        err = err ?: bpf_program__set_autoload(obj->progs.kprobe__commit_creds, false);
        err = err ?: bpf_program__set_autoload(obj->progs.kretprobe__inet_csk_accept, false);
        err = err ?: bpf_program__set_autoload(obj->progs.kprobe__tcp_v4_connect, false);
        err = err ?: bpf_program__set_autoload(obj->progs.kretprobe__tcp_v4_connect, false);
        err = err ?: bpf_program__set_autoload(obj->progs.kprobe__tcp_close, false);
    } else {
        err = err ?: bpf_program__set_autoload(obj->progs.fentry__do_unlinkat, false);
        err = err ?: bpf_program__set_autoload(obj->progs.fentry__mnt_want_write, false);
        err = err ?: bpf_program__set_autoload(obj->progs.fentry__vfs_unlink, false);
        err = err ?: bpf_program__set_autoload(obj->progs.fexit__vfs_unlink, false);
        err = err ?: bpf_program__set_autoload(obj->progs.fexit__do_filp_open, false);
        err = err ?: bpf_program__set_autoload(obj->progs.fentry__vfs_rename, false);
        err = err ?: bpf_program__set_autoload(obj->progs.fexit__vfs_rename, false);
        err = err ?: bpf_program__set_autoload(obj->progs.fentry__taskstats_exit, false);
        err = err ?: bpf_program__set_autoload(obj->progs.fentry__commit_creds, false);
        err = err ?: bpf_program__set_autoload(obj->progs.fexit__inet_csk_accept, false);
        err = err ?: bpf_program__set_autoload(obj->progs.fexit__tcp_v4_connect, false);
        err = err ?: bpf_program__set_autoload(obj->progs.fentry__tcp_close, false);
    }

    return err;
}

static bool system_has_bpf_tramp()
{
    /*
     * This is somewhat-fragile but as far as I can see, is the most robust
     * possible way to detect BPF trampoline support on any given kernel, (i.e.
     * if we can load "fentry/" and "fexit/" programs). BPF trampoline support
     * was introduced on x86 with kernel commit
     * fec56f5890d93fc2ed74166c397dc186b1c25951 in 5.5.
     *
     * To detect it, you not only need to load a BPF trampoline program, but
     * you also need to _attach_ to that program. Loading will succeed even if
     * BPF trampoline support is absent, only attaching will fail.
     *
     * To load + attach, we need to pass a BTF id to the attach_btf_id
     * corresponding to the BTF type (of kind BTF_KIND_FUNC) of a valid
     * function in the kernel that this program is supposed to be attached to.
     * Loading will otherwise fail. The most robust thing to do here would be
     * to iterate over the list of all BTF types and just pick the first one
     * where kind == BTF_KIND_FUNC (i.e. just pick an arbitrary function that
     * we know exists on the currently running kernel). Unfortunately this
     * isn't possible, as some functions are marked with the __init attribute
     * in the kernel, thus they cease to exist after bootup and can't be
     * attached to.
     *
     * Instead we just use the taskstats_exit function. It's been in the kernel
     * since 2006 and we already attach to it with a BPF probe, so if it's
     * removed, more visible parts of the code should break as well, indicating
     * this needs to be updated.
     */

    int prog_fd, attach_fd, btf_id;
    bool ret        = true;
    struct btf *btf = btf__load_vmlinux_btf();
    if (libbpf_get_error(btf)) {
        verbose("could not load system BTF (does the kernel have BTF?)\n");
        ret = false;
        goto out;
    }

    /*
     * r0 = 0
     * exit
     *
     * This could be done more clearly with BPF_MOV64_IMM and BPF_EXIT_INSN
     * macros in the kernel sources but unfortunately they're not exported to
     * userspace.
     */
    struct bpf_insn insns[] = {
        {.code    = BPF_ALU64 | BPF_MOV | BPF_K,
         .dst_reg = BPF_REG_0,
         .src_reg = 0,
         .off     = 0,
         .imm     = 0},
        {.code = BPF_EXIT | BPF_JMP, .dst_reg = 0, .src_reg = 0, .off = 0, .imm = 0}};
    int insns_cnt = 2;

    btf_id = btf__find_by_name(btf, "taskstats_exit");
    LIBBPF_OPTS(bpf_prog_load_opts, opts, .log_buf = NULL, .log_level = 0,
                .expected_attach_type = BPF_TRACE_FENTRY, .attach_btf_id = btf_id);
    prog_fd = bpf_prog_load(BPF_PROG_TYPE_TRACING, NULL, "GPL", insns, insns_cnt, &opts);
    if (prog_fd < 0) {
        ret = false;
        goto out_free_btf;
    }

    /*
     * NB: This is a confusingly named API: bpf(BPF_RAW_TRACEPOINT_OPEN, ...)
     * is used to attach an already-loaded BPF trampoline program (in addition
     * to a raw tracepoint).
     *
     * A new, more intuitively named API was added later called BPF_LINK_CREATE
     * (see kernel commit 8462e0b46fe2d4c56d0a7de705228e3bf1da03d9), but the
     * BPF_RAW_TRACEPOINT_OPEN approach should continue to work on all kernels
     * due to the kernel's userspace API guarantees.
     */
    attach_fd = bpf_raw_tracepoint_open(NULL, prog_fd);
    if (attach_fd < 0) {
        ret = false;
        goto out_close_prog_fd;
    }

    /* Successfully attached, we know BPF trampolines work, clean everything up */
    close(attach_fd);

out_close_prog_fd:
    close(prog_fd);
out_free_btf:
    btf__free(btf);
out:
    return ret;
}

static uint64_t detect_system_features()
{
    uint64_t features = 0;

    if (system_has_bpf_tramp())
        features |= EBPF_FEATURE_BPF_TRAMP;

    return features;
}

static bool system_has_btf(void)
{
    struct btf *btf = btf__load_vmlinux_btf();
    if (libbpf_get_error(btf)) {
        verbose("Kernel does not support BTF, bpf events are not supported\n");
        return false;
    } else {
        btf__free(btf);
        return true;
    }
}

static uint64_t get_kernel_version(void)
{
    int maj = 0, min = 0, patch = 0;

    // Ubuntu kernels do not report the true upstream kernel source version in
    // utsname.release, they report the "ABI version", which is the upstream
    // kernel major.minor with some extra ABI information, e.g.:
    // 5.15.0-48-generic. The upstream patch version is always set to 0.
    //
    // Ubuntu provides a file under procfs that reports the actual upstream
    // source version, so we use that instead if it exists.
    if (access("/proc/version_signature", R_OK) == 0) {
        FILE *f = fopen("/proc/version_signature", "r");
        if (f) {
            // Example: Ubuntu 5.15.0-48.54-generic 5.15.53
            if (fscanf(f, "%*s %*s %d.%d.%d\n", &maj, &min, &patch) == 3) {
                fclose(f);
                return KERNEL_VERSION(maj, min, patch);
            }

            fclose(f);
        }

        verbose("Ubuntu version file exists but could not be parsed, using uname\n");
    }

    struct utsname un;
    if (uname(&un) == -1) {
        verbose("uname failed: %d: %s\n", errno, strerror(errno));
        return 0;
    }

    char *debian_start = strstr(un.version, "Debian");
    if (debian_start != NULL) {
        // We're running on Debian.
        //
        // Like Ubuntu, what Debian reports in the un.release buffer is the
        // "ABI version", which is the major.minor of the upstream, with the
        // patch always set to 0 (and some further ABI numbers). e.g.:
        // 5.10.0-18-amd64
        //
        // See the following docs for more info:
        // https://kernel-team.pages.debian.net/kernel-handbook/ch-versions.html
        //
        // Unlike Ubuntu, Debian does not provide a special procfs file
        // indicating the actual upstream source. Instead, it puts the actual
        // upstream source version into the un.version field, after the string
        // "Debian":
        //
        // $ uname -a
        // Linux bullseye 5.10.0-18-amd64 #1 SMP Debian 5.10.140-1 (2022-09-02) x86_64 GNU/Linux
        //
        // $ uname -v
        // #1 SMP Debian 5.10.140-1 (2022-09-02)
        //
        // Due to this, we pull the upstream kernel source out of un.version here.
        if (sscanf(debian_start, "Debian %d.%d.%d", &maj, &min, &patch) != 3) {
            verbose("could not parse uname version string: %s\n", un.version);
            return 0;
        }

        return KERNEL_VERSION(maj, min, patch);
    }

    // We're not on Ubuntu or Debian, un.release should tell us the actual
    // upstream source
    if (sscanf(un.release, "%d.%d.%d", &maj, &min, &patch) != 3) {
        verbose("could not parse uname release string: %d: %s\n", errno, strerror(errno));
        return 0;
    }

    return KERNEL_VERSION(maj, min, patch);
}

static bool kernel_version_is_supported(void)
{
    // We only support Linux 5.10.16+
    //
    // Linux commit e114dd64c0071500345439fc79dd5e0f9d106ed (went in in
    // 5.11/5.10.16) fixed a verifier bug that (as of 9/28/2022) causes our
    // probes to fail to load.
    //
    // Theoretically, we could push support back to 5.8 without any
    // foundational changes (the BPF ringbuffer was added in 5.8, we'd need to
    // use per-cpu perfbuffers prior to that), but, for the time being, it's
    // been decided that this is more hassle than it's worth.
    uint64_t kernel_version = get_kernel_version();
    if (kernel_version < KERNEL_VERSION(5, 10, 16)) {
        verbose("kernel version is < 5.10.16 (version code: %x), bpf events are not supported\n",
                kernel_version);
        return false;
    }

    return true;
}

static int libbpf_verbose_print(enum libbpf_print_level lvl, const char *fmt, va_list args)
{
    return vfprintf(stderr, fmt, args);
}

static int verbose(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    if (!log_verbose)
        return 0;

    return vfprintf(stderr, fmt, args);
}

int ebpf_set_verbose_logging()
{
    libbpf_set_print(libbpf_verbose_print);
    log_verbose = true;
    return 0;
}

uint64_t ebpf_event_ctx__get_features(struct ebpf_event_ctx *ctx)
{
    return ctx->features;
}

int ebpf_event_ctx__new(struct ebpf_event_ctx **ctx, ebpf_event_handler_fn cb, uint64_t events)
{
    struct EventProbe_bpf *probe = NULL;
    struct btf *btf              = NULL;

    // Our probes aren't 100% guaranteed to load if these two facts are true
    // e.g. maybe someone compiled a kernel without kprobes or bpf trampolines.
    // However, checking these two things should cover the vast majority of
    // failure cases, allowing us to print a more understandable message than
    // what you'd get if you just tried to load the probes.
    if (!kernel_version_is_supported() || !system_has_btf()) {
        verbose("this system does not support BPF events (see logs)\n");
        return -ENOTSUP;
    }

    // ideally we'd be calling
    //
    // ```c
    // libbpf_set_strict_mode(LIBBPF_STRICT_AUTO_RLIMIT_MEMLOCK);
    // ```
    //
    // to automatically detect if `RLIMIT_MEMLOCK` needs increasing, however
    // with kernel 5.10.109+ on GKE, it incorrectly detects that bpf uses memcg
    // instead of memlock rlimit, so it does nothing.
    //
    // The check for memcg loads a program with the `bpf_ktime_get_coarse_ns`
    // helper in order to check for memcg memory accounting, which was added
    // around the same time the memory account change took place (5.11). This
    // helper is backported in 5.10.109+ making the detection mechanism faulty,
    // so instead we just blindy set `RLIMIT_MEMLOCK` to infinity for now.

    struct rlimit rlim = {
        .rlim_cur = RLIM_INFINITY,
        .rlim_max = RLIM_INFINITY,
    };

    int err = setrlimit(RLIMIT_MEMLOCK, &rlim);
    if (err != 0)
        goto out_destroy_probe;

    uint64_t features = detect_system_features();

    btf = btf__load_vmlinux_btf();
    if (libbpf_get_error(btf)) {
        verbose("could not load system BTF (does the kernel have BTF?)\n");
        err = -ENOENT;
        goto out_destroy_probe;
    }

    probe = EventProbe_bpf__open();
    if (probe == NULL) {
        /* EventProbe_bpf__open doesn't report errors, hard to find something
         * that fits perfect here
         */
        err = -ENOENT;
        goto out_destroy_probe;
    }

    probe->rodata->consumer_pid = getpid();

    err = probe_fill_relos(btf, probe);
    if (err != 0)
        goto out_destroy_probe;

    err = probe_resize_maps(probe);
    if (err != 0)
        goto out_destroy_probe;

    err = probe_set_autoload(btf, probe, features);
    if (err != 0)
        goto out_destroy_probe;

    err = EventProbe_bpf__load(probe);
    if (err != 0)
        goto out_destroy_probe;

    err = EventProbe_bpf__attach(probe);
    if (err != 0)
        goto out_destroy_probe;

    if (!ctx)
        goto out_destroy_probe;

    *ctx = calloc(1, sizeof(struct ebpf_event_ctx));
    if (*ctx == NULL) {
        err = -ENOMEM;
        goto out_destroy_probe;
    }
    (*ctx)->probe    = probe;
    (*ctx)->features = features;
    probe            = NULL;

    struct ring_buffer_opts rb_opts;
    rb_opts.sz = sizeof(rb_opts);

    (*ctx)->cb_ctx = calloc(1, sizeof(struct ring_buf_cb_ctx));
    if ((*ctx)->cb_ctx == NULL) {
        err = -ENOMEM;
        goto out_destroy_probe;
    }

    (*ctx)->cb_ctx->cb          = cb;
    (*ctx)->cb_ctx->events_mask = events;

    (*ctx)->ringbuf = ring_buffer__new(bpf_map__fd((*ctx)->probe->maps.ringbuf), ring_buf_cb,
                                       (*ctx)->cb_ctx, &rb_opts);

    if ((*ctx)->ringbuf == NULL) {
        /* ring_buffer__new doesn't report errors, hard to find something that
         * fits perfect here
         */
        err = -ENOENT;
        goto out_destroy_probe;
    }

    return ring_buffer__epoll_fd((*ctx)->ringbuf);

out_destroy_probe:
    btf__free(btf);
    if (probe)
        EventProbe_bpf__destroy(probe);
    ebpf_event_ctx__destroy(ctx);
    return err;
}

int ebpf_event_ctx__next(struct ebpf_event_ctx *ctx, int timeout)
{
    if (!ctx)
        return -1;

    int consumed = ring_buffer__poll(ctx->ringbuf, timeout);
    return consumed > 0 ? 0 : consumed;
}

int ebpf_event_ctx__poll(struct ebpf_event_ctx *ctx, int timeout)
{
    if (!ctx)
        return -1;

    return ring_buffer__poll(ctx->ringbuf, timeout);
}

int ebpf_event_ctx__consume(struct ebpf_event_ctx *ctx)
{
    if (!ctx)
        return -1;

    return ring_buffer__consume(ctx->ringbuf);
}

void ebpf_event_ctx__destroy(struct ebpf_event_ctx **ctx)
{
    if (!ctx)
        return;

    if (*ctx) {
        if ((*ctx)->ringbuf) {
            ring_buffer__free((*ctx)->ringbuf);
        }
        if ((*ctx)->probe) {
            EventProbe_bpf__destroy((*ctx)->probe);
        }
        if ((*ctx)->cb_ctx) {
            free((*ctx)->cb_ctx);
            (*ctx)->cb_ctx = NULL;
        }
        free(*ctx);
        *ctx = NULL;
    }
}

struct bpf_map *ebpf_event_get_trustlist_map(struct ebpf_event_ctx *ctx)
{
    if (NULL == ctx) {
        verbose("ebpf ctx is NULL");
        return NULL;
    }
    struct EventProbe_bpf *probe = ctx->probe;
    if (NULL == probe) {
        verbose("Ebpf events probe is NULL");
        return NULL;
    }
    struct bpf_map *map = probe->maps.elastic_ebpf_events_trusted_pids;
    if (NULL == map) {
        verbose("Ebpf trusted pids map is NULL");
        return NULL;
    }
    return map;
}

static int ebpf_clear_process_trustlist(int map_fd)
{
    int rv                   = 0;
    uint8_t key_buf[64]      = {0};
    uint8_t next_key_buf[64] = {0};

    // get the first key
    if (bpf_map_get_next_key(map_fd, NULL, key_buf) < 0) {
        if (errno == ENOENT) {
            // map is already empty
            rv = 0;
            return rv;
        } else {
            // failure (perhaps not supported)
            verbose("Error getting next key while clearing trusted pids map, errno=%d\n", errno);
            rv = -1;
            return rv;
        }
    }

    // iterate over map
    while (0 == bpf_map_get_next_key(map_fd, key_buf, next_key_buf)) {
        // return value 0 means 'key' exists and 'next_key' has been set
        (void)bpf_map_delete_elem(map_fd, key_buf);
        memcpy(key_buf, next_key_buf, sizeof(key_buf));
    }

    // -1 was returned so 'key' is the last element - delete it
    (void)bpf_map_delete_elem(map_fd, key_buf);

    return 0;
}

int ebpf_set_process_trustlist(struct bpf_map *map, uint32_t *pids, int count)
{
    int rv = 0;

    if (!map || libbpf_get_error(map)) {
        verbose("Error: invalid trustlist map, errno=%d\n", errno);
        rv = -1;
        return rv;
    }

    int map_fd = bpf_map__fd(map);
    if (map_fd < 0) {
        verbose("Error: invalid trustlist map fd, errno=%d\n", errno);
        rv = -1;
        return rv;
    }
    // first clear the entire map
    rv = ebpf_clear_process_trustlist(map_fd);
    if (rv) {
        verbose("Error: failed to clear trusted pids map, errno=%d\n", errno);
        return rv;
    }

    // add entries to trustlist
    int i = 0;
    for (i = 0; i < count; i++) {
        uint32_t val = 1;
        uint32_t pid = pids[i];
        rv           = bpf_map_update_elem(map_fd, &pid, &val, BPF_ANY);
        if (rv) {
            verbose("Error: failed to add entry to trusted pids map, errno=%d\n", errno);
            return rv;
        }
    }

    return rv;
}
