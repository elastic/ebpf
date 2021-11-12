// SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License 2.0;
 * you may not use this file except in compliance with the Elastic License 2.0.
 */

// This file is just a spec for discussion, not included in builds or anything.
// This does not compile and it's probably not in the folder we want it in.

#ifndef LIBEBPF_H_
#define LIBEBPF_H_

#include <stdint.h>
#include <sys/types.h>

/* Kernel Features */
enum ebpf_kernel_features {
    EBPF_KERNEL_CAPABLE_BPF = (1 << 0),
    EBPF_KERNEL_CAPABLE_RINGBUF = (1 << 1),
    EBPF_KERNEL_CAPABLE_BTF = (1 << 2),
};

int ebpf_kernel__detect_features();

/* Events fetching and manipulation */
typedef enum ebpf_event_type {
    EBPF_EVENT_TYPE_UNSPEC = 0,
    EBPF_EVENT_TYPE_NETWORK_UPDATE = 1,
    EVENT_NETWORK_IPV4_CONNECTION_ATTEMPTED = 2,
    EVENT_NETWORK_IPV4_DISCONNECT_RECEIVED  = 3,
    EVENT_NETWORK_IPV4_CONNECTION_ACCEPTED  = 4,
    EVENT_NETWORK_IPV4_RECONNECT_ATTEMPTED  = 5,
    EVENT_NETWORK_IPV4_HTTP_REQUEST         = 6,
    EVENT_NETWORK_IPV6_CONNECTION_ATTEMPTED = 7,
    EVENT_NETWORK_IPV6_DISCONNECT_RECEIVED  = 8,
    EVENT_NETWORK_IPV6_CONNECTION_ACCEPTED  = 9,
    EVENT_NETWORK_IPV6_RECONNECT_ATTEMPTED  = 10,
    EVENT_NETWORK_IPV6_HTTP_REQUEST         = 11,
    EBPF_EVENT_MAX
} ebpf_event_type;

struct ebpf_event {
    uint64_t ts;
    ebpf_event_type type;
    void *data;
};

typedef int (*event_handler_fn)(struct ebpf_event *event, size_t);

void *ebpf_event__buffer_new(event_handler_fn handler);
void ebpf_event__next(void *buffer);

#endif // LIBEBPF_H_
