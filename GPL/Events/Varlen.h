// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2022 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

// Utilities for dealing with variable-length fields

#ifndef EBPF_EVENTS_VARLEN_H
#define EBPF_EVENTS_VARLEN_H

#include "EbpfEventProto.h"

// We can't use the ringbuf reserve/commit API if we want to output an event
// with variable length fields as we won't know the event size in advance, so
// we create events on the event_buffer_map if this is the case and output them
// with bpf_ringbuf_output.
//
// If the event has no variable length parameters (i.e. is always a fixed
// size). bpf_ringbuf_reserve/bpf_ringbuf_submit should be used instead to
// avoid the extra memory copy for better performance.

// 256 KiB per cpu core, of which 128 KiB is useable as we have to bound each
// new variable-length field to start at no more than half the size of the
// buffer to make the verifier happy.
//
// 128 KiB is currently more than large enough to handle the largest
// theoretical event, but should be bumped in the future if that changes or
// else the verifier will start to complain.
#define EVENT_BUFFER_SIZE (1 << 18)
#define EVENT_BUFFER_SIZE_HALF (EVENT_BUFFER_SIZE >> 1)
#define EVENT_BUFFER_SIZE_HALF_MASK (EVENT_BUFFER_SIZE_HALF - 1)

// Convenience macro to determine the current size of an event with its
// variable length fields
//
// We logical and with (EVENT_BUFFER_SIZE - 1). This puts both an upper and
// lower bound on the value so that we have 0 <= value < EVENT_BUFFER_SIZE, and
// the verifier is happy.
#define EVENT_SIZE(x) ((sizeof(*x) + x->vl_fields.size) & (EVENT_BUFFER_SIZE - 1))

// Using a BPF_MAP_TYPE_PERCPU_ARRAY here would be simpler but unfortunately we
// can't use one. The allocation of map values for a BPF_MAP_TYPE_PERCPU_ARRAY
// is done under the hood by Linux's percpu allocator, which has a maximum
// allocation size of 32 KiB (See PCPU_MIN_UNIT_SIZE in include/linux/percpu.h
// as of Linux 6.0). Trying to create a BPF_MAP_TYPE_PERCPU_ARRAY with a value
// size larger than 32 KiB will result in -ENOMEM.
//
// This is too small for us, so instead we implement a percpu array ourselves
// using a BPF_MAP_TYPE_ARRAY. We resize it in userspace to $(nproc) elements
// and access it through the get_event_buffer helper, which returns the value
// corresponding to the current processor.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, EVENT_BUFFER_SIZE);
    __uint(max_entries, 0); // Will be resized by userspace to $(nproc)
} event_buffer_map SEC(".maps");

static void *get_event_buffer()
{
    int key = bpf_get_smp_processor_id();
    return bpf_map_lookup_elem(&event_buffer_map, &key);
}

struct ebpf_varlen_field *ebpf_vl_field__add(struct ebpf_varlen_fields_start *fields,
                                             enum ebpf_varlen_field_type type)
{
    struct ebpf_varlen_field *new_field =
        (struct ebpf_varlen_field *)(&fields->data[fields->size & EVENT_BUFFER_SIZE_HALF_MASK]);
    new_field->type = type;
    fields->nfields++;
    return new_field;
}

void ebpf_vl_fields__init(struct ebpf_varlen_fields_start *fields)
{
    fields->nfields = 0;
    fields->size    = 0;
}

void ebpf_vl_field__set_size(struct ebpf_varlen_fields_start *vl_fields,
                             struct ebpf_varlen_field *field,
                             size_t size)
{
    vl_fields->size += size + sizeof(struct ebpf_varlen_field);
    field->size = size;
}

#endif // EBPF_EVENTS_VARLEN_H
