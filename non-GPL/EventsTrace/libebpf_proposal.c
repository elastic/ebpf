// SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License 2.0;
 * you may not use this file except in compliance with the Elastic License 2.0.
 */

#include "libebpf.h"
#include <bpf/libbpf.h>
#include <stdio.h>

struct ebpf_event_ctx {
    char something[64];
};

// This is just an **example implementation** to see how the proposed header could look like
// when it is implemented. Might not even work, just for us to be aligned.
// you can compile it with "make libebpf_proposal" in the build dir
// If you want to experiment with it we also have a dummy binary that uses
// it, compile it with `make libebpf_cli`

int ebpf_event__buffer_new(struct ebpf_event_ctx **ctx, ebpf_cap_set cap_set, ebpf_event_set event_set)
{
    // This will check if ring buffers are supported and call
    // ring_buffer__new if they are, if they are not it will
    // create a perf buffer with `perf_buffer_new

    //  int map_fd = 1; // TODO: this will need to be retrieved from the program

    // if (ebpf_kernel__detect_features() & EBPF_KERNEL_CAPABLE_RINGBUF) {
    //     return ring_buffer__new(map_fd, ebpf_event__buffer_ringbuf_cb(handler), NULL, NULL);
    // }

    // struct perf_buffer_opts pb_opts;
    // pb_opts.sample_cb = ebpf_event__buffer_perf_cb(handler);
    // return perf_buffer__new(map_fd, 8, &pb_opts);

    return -1;
}

int ebpf_event__next(
        struct ebpf_event_ctx *ctx,
        ebpf_event_handler_fn *handler_func)
{
    // // TODO: we could replace this stuff with the epool counterparts as Norrie was suggesting.
    // if (ebpf_kernel__detect_features() & EBPF_KERNEL_CAPABLE_RINGBUF) {
    //     return ring_buffer__epoll_fd(buffer);
    // }
    // return perf_buffer__epoll_fd(buffer);
    return 0;
}


void ebpf_event__cleanup(struct ebpf_event_ctx *ctx) {
    // todo, also remember to ask if this is about event or buffer cleanup?
}
