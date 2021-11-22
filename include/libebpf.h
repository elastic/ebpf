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
    EBPF_EVENT_PROCESS_FORK = (1 << 1),
    EBPF_EVENT_PROCESS_EXEC = (1 << 2),
    EBPF_EVENT_PROCESS_EXIT = (1 << 3),
    EBPF_EVENT_PROCESS_TTY_OUTPUT = (1 << 4),
    EBPF_EVENT_FILE_CREATE = (1 << 5),
    EBPF_EVENT_FILE_DELETE = (1 << 6),
    EBPF_EVENT_FILE_RENAME  = (1 << 7),
    EBPF_EVENT_FILE_OPEN = (1 << 8),
    EBPF_EVENT_FILE_EXCHANGE = (1 << 9),
    EBPF_EVENT_INTERNAL_FILE_OPEN = (1 << 10),
    EBPF_EVENT_INTERNAL_FILE_CLOSE = (1 << 11),
    EBPF_EVENT_INTERNAL_FILE_CHDIR = (1 << 12),
    EBPF_EVENT_INTERNAL_FILE_DUP = (1 << 13),
} ebpf_event_type;

struct ebpf_event {
    uint64_t ts;
    ebpf_event_type type;
    void *data;
};

/* opaque context, will contain union with struct perf_buffer,
 * struct ring_buffer,
 *
 * we need a way to map from capability/event sets to probe sets,
 * and we could store the cap/event sets directly or cache the result
 * of the mapping in the context */
typedef struct ebpf_event_ctx;

typedef int (*ebpf_event_handler_fn)(struct ebpf_event *event, size_t);

typedef ebpf_event_type ebpf_cap_set;

/* result will be ((ACTUAL AND INTERESTED) OR FORCED) */
ebpf_cap_set ebpf_event__detect_capabilities(
        ebpf_cap_set interested,
        ebpf_cap_set forced);

/* Combination of events user is interested in. Mapping of events
 * to probe that provides that event is stored internally. User
 * does not need to know which probes to load */
typedef uint64_t ebpf_event_set;

/* allocates a new context based on requested events and capabilities.
 *
 * returns a positive int that represents an fd, which
 * can be used with epoll on success. returns -1 and
 * sets errno on failure
 */
int ebpf_event__buffer_new(
        ebpf_event_ctx **ctx,
        ebpf_cap_set,
        ebpf_event_set);

/* this func will not return data unless fd is ready
 * so user will supply their own epoll and call this
 * func when fd is readable. I think passing a handler
 * function is more versatile than passing a buffer?
 * no strong feelings on that. The handler will likely
 * dispatch one of another layer of callbacks switched
 * on event type.
 *
 * We should also discuss blocking/nonblocking semantics
 * here. I think this function could return -1 and set
 * errno to -EAGAIN if the context is in a nonblocking
 * state but no data is available. */
int ebpf_event__next(
        ebpf_event_ctx *ctx,
        event_handler_fn *handler_func);

void ebpf_event__cleanup(
        ebpf_event_ctx *ctx);

#endif // LIBEBPF_H_
