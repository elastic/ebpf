// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V.
 * under one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#ifndef EBPF_EVENTS_H_
#define EBPF_EVENTS_H_

#include <stddef.h>

#include "EbpfEventProto.h"

enum ebpf_kernel_features {
    EBPF_KERNEL_FEATURE_BPF     = (1 << 0),
    EBPF_KERNEL_FEATURE_RINGBUF = (1 << 1),
    EBPF_KERNEL_FEATURE_BTF     = (1 << 2),
};

/* Opaque context */
struct ebpf_event_ctx;

typedef int (*ebpf_event_handler_fn)(struct ebpf_event_header *);

/* Allocates a new context based on requested events and capabilities.
 *
 * If ctx is NULL, the function returns right after loading and attaching the
 * libbpf skeleton.
 *
 * Returns a positive int that represents an fd, which can be used with epoll
 * on success. Returns an error on failure. If ctx is NULL,
 * returns 0 on success or less than 0 on failure.
 */
int ebpf_event_ctx__new(struct ebpf_event_ctx **ctx,
                        ebpf_event_handler_fn cb,
                        uint64_t features,
                        uint64_t events);

/* Consumes as many events as possible from the event context and returns the
 * number consumed.
 */
int ebpf_event_ctx__next(struct ebpf_event_ctx *ctx, int timeout);

void ebpf_event_ctx__destroy(struct ebpf_event_ctx **ctx);

#endif // EBPF_EVENTS_H_
