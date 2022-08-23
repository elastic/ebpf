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

bool verbose_log = false;
static int ebpf_log(const char *fmt, ...);

struct ring_buf_cb_ctx {
    ebpf_event_handler_fn cb;
    uint64_t events_mask;
};

struct ebpf_event_ctx {
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

    // TODO: Re-enable tty_write probe when BTF issues are fixed
#if 0
    if (FILL_FUNC_ARG_EXISTS(obj, btf, tty_write, from)) {
        err = err ?: FILL_FUNC_ARG_IDX(obj, btf, tty_write, buf);
        err = err ?: FILL_FUNC_ARG_IDX(obj, btf, tty_write, count);
    } else {
        err = err ?: FILL_FUNC_ARG_IDX(obj, btf, tty_write, from);
    }
#endif

    return err;
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
        // TODO: Re-enable tty_write probe when BTF issues are fixed
#if 0
        err = err ?: bpf_program__set_autoload(obj->progs.kprobe__tty_write, false);
#endif
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
        // TODO: Re-enable tty_write probe when BTF issues are fixed
#if 0
        err = err ?: bpf_program__set_autoload(obj->progs.fentry__tty_write, false);
#endif
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
        ebpf_log("could not load system BTF (does the kernel have BTF?)");
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

int ebpf_detect_system_features(uint64_t *features)
{
    if (!features)
        return -EINVAL;

    *features = 0;
    if (system_has_bpf_tramp())
        *features |= EBPF_FEATURE_BPF_TRAMP;

    return 0;
}

static int libbpf_verbose_print(enum libbpf_print_level lvl, const char *fmt, va_list args)
{
    return vfprintf(stderr, fmt, args);
}

static int ebpf_log(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);

    if (!verbose_log)
        return 0;

    return vfprintf(stderr, fmt, args);
}

int ebpf_set_verbose_logging()
{
    libbpf_set_print(libbpf_verbose_print);
    verbose_log = true;
    return 0;
}

int ebpf_event_ctx__new(struct ebpf_event_ctx **ctx,
                        ebpf_event_handler_fn cb,
                        struct ebpf_event_ctx_opts opts)
{
    struct EventProbe_bpf *probe = NULL;
    struct btf *btf              = NULL;

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

    btf = btf__load_vmlinux_btf();
    if (libbpf_get_error(btf)) {
        ebpf_log("could not load system BTF (does the kernel have BTF?)");
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

    err = probe_set_autoload(btf, probe, opts.features);
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
    (*ctx)->probe = probe;
    probe         = NULL;

    struct ring_buffer_opts rb_opts;
    rb_opts.sz = sizeof(rb_opts);

    (*ctx)->cb_ctx = calloc(1, sizeof(struct ring_buf_cb_ctx));
    if ((*ctx)->cb_ctx == NULL) {
        err = -ENOMEM;
        goto out_destroy_probe;
    }

    (*ctx)->cb_ctx->cb          = cb;
    (*ctx)->cb_ctx->events_mask = opts.events;

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
