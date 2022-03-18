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
#define FILL_FUNC_ARG_IDX(ctx, btf, func, arg)                                                     \
    ({                                                                                             \
        int __r = -1;                                                                              \
        int r   = resolve_btf_func_arg_idx(btf, #func, #arg);                                      \
        if (r >= 0)                                                                                \
            __r = 0;                                                                               \
        (*ctx)->probe->rodata->arg__##func##__##arg##__ = r;                                       \
        __r;                                                                                       \
    })

/* Given a function name, returns the "ret" argument index. */
#define FILL_FUNC_RET_IDX(ctx, btf, func)                                                          \
    ({                                                                                             \
        int __r = -1;                                                                              \
        int r   = resolve_btf_func_ret_idx(btf, #func);                                            \
        if (r >= 0)                                                                                \
            __r = 0;                                                                               \
        (*ctx)->probe->rodata->ret__##func##__ = r;                                                \
        __r;                                                                                       \
    })

/* Given a function name and an argument name, returns whether the argument
 * exists or not.
 */
#define FILL_FUNC_ARG_EXISTS(ctx, btf, func, arg)                                                  \
    ({                                                                                             \
        int __r = -1;                                                                              \
        int r   = resolve_btf_func_arg_idx(btf, #func, #arg);                                      \
        if (r >= 0) {                                                                              \
            (*ctx)->probe->rodata->exists__##func##__##arg##__ = true;                             \
            __r                                                = 0;                                \
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
static int fill_ctx_relos(struct btf *btf, struct ebpf_event_ctx **ctx)
{
    int err = -1;

    err = FILL_FUNC_ARG_IDX(ctx, btf, vfs_unlink, dentry);
    if (err)
        goto out;

    err = FILL_FUNC_RET_IDX(ctx, btf, vfs_unlink);
    if (err)
        goto out;

    if (FILL_FUNC_ARG_EXISTS(ctx, btf, vfs_rename, rd)) {
        /* We are on a 5.12- kernel */
        err = FILL_FUNC_ARG_IDX(ctx, btf, vfs_rename, old_dentry);
        if (err)
            goto out;
        err = FILL_FUNC_ARG_IDX(ctx, btf, vfs_rename, new_dentry);
        if (err)
            goto out;
    }
    err = FILL_FUNC_RET_IDX(ctx, btf, vfs_rename);
    if (err)
        goto out;

out:
    return err;
}

/* Certain programs are available only if certain requirements are met.
 *
 * E.g. `do_renameat2` is not present in a 5.10 BTF, so tracepoints for the rename
 * syscalls will be loaded instead.
 */
static inline int probe_set_autoload(struct btf *btf, struct EventProbe_bpf *obj)
{
    int err = 0;

    if (BTF_FUNC_EXISTS(btf, do_renameat2)) {
        err = bpf_program__set_autoload(obj->progs.tracepoint_sys_enter_rename, false);
        if (err)
            goto out;
        err = bpf_program__set_autoload(obj->progs.tracepoint_sys_enter_renameat, false);
        if (err)
            goto out;
        err = bpf_program__set_autoload(obj->progs.tracepoint_sys_enter_renameat2, false);
        if (err)
            goto out;
    } else {
        err = bpf_program__set_autoload(obj->progs.fentry__do_renameat2, false);
        if (err)
            goto out;
    }

out:
    return err;
}

int ebpf_event_ctx__new(struct ebpf_event_ctx **ctx,
                        ebpf_event_handler_fn cb,
                        uint64_t features,
                        uint64_t events,
                        bool poke_load_attach)
{
    int err = 0;

    struct btf *btf = btf__load_vmlinux_btf();
    if (libbpf_get_error(btf))
        goto out_destroy_probe;

    *ctx    = calloc(1, sizeof(struct ebpf_event_ctx));
    if (*ctx == NULL) {
        err = -ENOMEM;
        goto out_destroy_probe;
    }

    (*ctx)->probe = EventProbe_bpf__open();
    if ((*ctx)->probe == NULL) {
        /* EventProbe_bpf__open doesn't report errors, hard to find something
         * that fits perfect here
         */
        err = -ENOENT;
        goto out_destroy_probe;
    }

    err = fill_ctx_relos(btf, ctx);
    if (err < 0)
        goto out_destroy_probe;

    err = probe_set_autoload(btf, (*ctx)->probe);
    if (err != 0)
        goto out_destroy_probe;

    err = EventProbe_bpf__load((*ctx)->probe);
    if (err != 0)
        goto out_destroy_probe;

    err = EventProbe_bpf__attach((*ctx)->probe);
    if (err != 0)
        goto out_destroy_probe;

    if (poke_load_attach)
        goto out_destroy_probe;

    struct ring_buffer_opts opts;
    opts.sz = sizeof(opts);

    (*ctx)->cb_ctx = calloc(1, sizeof(struct ring_buf_cb_ctx));
    if ((*ctx)->cb_ctx == NULL) {
        err = -ENOMEM;
        goto out_destroy_probe;
    }

    (*ctx)->cb_ctx->cb          = cb;
    (*ctx)->cb_ctx->events_mask = events;

    (*ctx)->ringbuf = ring_buffer__new(bpf_map__fd((*ctx)->probe->maps.ringbuf), ring_buf_cb,
                                       (*ctx)->cb_ctx, &opts);

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
