// SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

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

typedef int (*ebpf_event_handler_fn)(struct ebpf_event *, size_t);

/* Allocates a new context based on requested events and capabilities.
 *
 * returns a positive int that represents an fd, which can be used with epoll
 * on success. returns an error on failure.
 */
int ebpf_event_ctx__new(
        struct ebpf_event_ctx **ctx,
        ebpf_event_handler_fn cb,
        uint64_t features,
        uint64_t events);

/* Consumes as many events as possible from the event context and returns the
 * number consumed.
 */
int ebpf_event_ctx__next(
        struct ebpf_event_ctx *ctx);

void ebpf_event_ctx__destroy(
        struct ebpf_event_ctx *ctx);

#endif // EBPF_EVENTS_H_
