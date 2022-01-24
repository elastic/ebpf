// SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

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

const struct btf_type *resolve_btf_type_by_func_name(struct btf *btf, const char *func_name)
{
    for (int i = 0; i < btf__type_cnt(btf); i++) {
        int btf_type = btf__resolve_type(btf, i);
        if (btf_type < 0)
            continue;

        const struct btf_type *btf_type_ptr = btf__type_by_id(btf, btf_type);

        if (!btf_is_func(btf_type_ptr))
            continue;

        const char *name = btf__name_by_offset(btf, btf_type_ptr->name_off);
        if (!strcmp(name, func_name) == 0)
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
static int resolve_btf_func_arg_id(const char *func_name, const char *arg_name)
{
    int ret = -1;
    struct btf *btf;

    btf = btf__load_vmlinux_btf();

    if (libbpf_get_error(btf))
        goto out;

    const struct btf_type *proto_btf_type_ptr = resolve_btf_type_by_func_name(btf, func_name);
    if (!proto_btf_type_ptr)
        goto out;

    struct btf_param *params = btf_params(proto_btf_type_ptr);
    for (int j = 0; j < btf_vlen(proto_btf_type_ptr); j++) {
        const char *cur_name = btf__name_by_offset(btf, params[j].name_off);
        if (strcmp(cur_name, arg_name) == 0) {
            ret = j;
            goto out;
        }
    }

out:
    return ret;
}

/* Find the BTF relocation index for a func return value */
static int resolve_btf_func_ret(const char *func_name)
{
    int ret = -1;
    struct btf *btf;

    btf = btf__load_vmlinux_btf();

    if (libbpf_get_error(btf))
        goto out;

    const struct btf_type *proto_btf_type_ptr = resolve_btf_type_by_func_name(btf, func_name);
    if (!proto_btf_type_ptr)
        goto out;

    ret = btf_vlen(proto_btf_type_ptr);
out:
    return ret;
}

#define FILL_FUNCTION_RELO(ctx, func_name, arg_name)                                               \
    ({                                                                                             \
        int __r = 0;                                                                               \
        (*ctx)->probe->rodata->arg__##func_name##__##arg_name##__ =                                \
            resolve_btf_func_arg_id(#func_name, #arg_name);                                        \
        if ((*ctx)->probe->rodata->arg__##func_name##__##arg_name##__ < 0)                         \
            __r = -1;                                                                              \
        __r;                                                                                       \
    })

#define FILL_FUNCTION_RET_RELO(ctx, func_name)                                                     \
    ({                                                                                             \
        int __r                                     = 0;                                           \
        (*ctx)->probe->rodata->ret__##func_name##__ = resolve_btf_func_ret(#func_name);            \
        if ((*ctx)->probe->rodata->ret__##func_name##__ < 0)                                       \
            __r = -1;                                                                              \
        __r;                                                                                       \
    })

/* Fill context relocations for kernel functions
 * You can add additional functions here by using the FILL_FUNCTION_RELO macro
 * Remember to declare it in `EventProbe.bpf.c` using the DECL_RELO_FUNC_ARGUMENT macro
 */
static int fill_ctx_relos(struct ebpf_event_ctx **ctx)
{
    int err = 0;
    err     = FILL_FUNCTION_RELO(ctx, vfs_unlink, dentry);
    err     = FILL_FUNCTION_RET_RELO(ctx, vfs_unlink);
    return err;
}

int ebpf_event_ctx__new(struct ebpf_event_ctx **ctx,
                        ebpf_event_handler_fn cb,
                        uint64_t features,
                        uint64_t events)
{
    int err = 0;
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

    err = fill_ctx_relos(ctx);
    if (err < 0)
        goto out_destroy_probe;

    err = EventProbe_bpf__load((*ctx)->probe);
    if (err != 0)
        goto out_destroy_probe;

    err = EventProbe_bpf__attach((*ctx)->probe);
    if (err != 0)
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
