// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#define __aligned_u64 __u64 __attribute__((aligned(8)))
#include "LibEbpfEvents.h"

#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>

#include "EventProbe.skel.h"

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
    ebpf_event_handler_fn cb       = cb_ctx->cb;
    struct ebpf_event_header *evt  = data;
    if (evt->type & cb_ctx->events_mask) {
        return cb(evt);
    }
    return 0;
}

const struct btf_type *resolve_btf_type_by_func(struct btf *btf, const char *func)
{
    for (int i = 0; i < btf__type_cnt(btf); i++) {
        int btf_type = btf__resolve_type(btf, i);
        if (btf_type < 0)
            continue;

        const struct btf_type *btf_type_ptr = btf__type_by_id(btf, btf_type);

        if (!btf_is_func(btf_type_ptr))
            continue;

        const char *name = btf__name_by_offset(btf, btf_type_ptr->name_off);
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
    int ret                                   = -1;
    const struct btf_type *proto_btf_type_ptr = resolve_btf_type_by_func(btf, func);
    if (!proto_btf_type_ptr)
        goto out;

    struct btf_param *params = btf_params(proto_btf_type_ptr);
    for (int j = 0; j < btf_vlen(proto_btf_type_ptr); j++) {
        const char *cur_name = btf__name_by_offset(btf, params[j].name_off);
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

static void probe_set_features(uint64_t *features)
{
    // default attach type for BPF_PROG_TYPE_TRACING is
    // BPF_TRACE_FENTRY.
    if (!libbpf_probe_bpf_prog_type(BPF_PROG_TYPE_TRACING, NULL))
        *features |= EBPF_FEATURE_BPF_TRAMP;
}

static int libbpf_verbose_print(enum libbpf_print_level lvl, const char *fmt, va_list args)
{
    return vfprintf(stderr, fmt, args);
}

int ebpf_set_verbose_logging()
{
    libbpf_set_print(libbpf_verbose_print);
}

int ebpf_event_ctx__new(struct ebpf_event_ctx **ctx,
                        ebpf_event_handler_fn cb,
                        struct ebpf_event_ctx_opts opts)
{
    int err                      = 0;
    struct EventProbe_bpf *probe = NULL;

    struct btf *btf = btf__load_vmlinux_btf();
    if (libbpf_get_error(btf))
        goto out_destroy_probe;

    probe = EventProbe_bpf__open();
    if (probe == NULL) {
        /* EventProbe_bpf__open doesn't report errors, hard to find something
         * that fits perfect here
         */
        err = -ENOENT;
        goto out_destroy_probe;
    }

    if (opts.features_autodetect)
        probe_set_features(&opts.features);

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
