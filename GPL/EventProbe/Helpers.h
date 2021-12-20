// SPDX-License-Identifier: GPL-2.0

/*
 * Elastic eBPF
 * Copyright 2021 Elasticsearch BV
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */

#ifndef EBPF_EVENTS_HELPERS_H
#define EBPF_EVENTS_HELPERS_H

#include "EbpfEventProto.h"

static __always_inline u64 ebpf_event__type_size(uint64_t event_type)
{
    switch (event_type)
    {
        case EBPF_EVENT_FILE_DELETE:
            return sizeof(struct ebpf_event_file_delete_data);
        case EBPF_EVENT_PROCESS_FORK:
            return sizeof(struct ebpf_event_process_fork_data);
        case EBPF_EVENT_PROCESS_EXEC:
            return sizeof(struct ebpf_event_process_exec_data);
        default:
            return 0;
    }
}

static __always_inline void *ebpf_event__new(void *ringbuf, uint64_t event_type)
{
    u64 specialized_event_size = ebpf_event__type_size(event_type);
    struct ebpf_event *event = NULL;

    event = bpf_ringbuf_reserve(ringbuf, sizeof(struct ebpf_event) + specialized_event_size, 0);
    if (!event)
    {
        goto out;
    }

    event->type = event_type;
    event->ts = bpf_ktime_get_ns();

out:
    return event;
}

static __always_inline int ebpf_event_file_path__from_dentry(struct ebpf_event_file_path *dst, struct dentry* src)
{
    size_t filepart_length;
    struct dentry *parent_dentry = NULL;
    struct dentry *current_dentry = NULL;

    size_t dentries_len = 0;

    struct dentry* dentries[MAX_PATH_DEPTH] = {};

    dentries[0] = src;

    for (int i = 0; i < MAX_PATH_DEPTH; i++)
    {
        if (i == 0)
        {
            parent_dentry = BPF_CORE_READ(src, d_parent);
            current_dentry = parent_dentry;
        }
        else
        {
            current_dentry = BPF_CORE_READ(parent_dentry, d_parent);
            if (current_dentry == parent_dentry)
            {
                break;
            }
            parent_dentry = current_dentry;
        }

        if (i + 1 < MAX_PATH_DEPTH)
        {
            dentries[i + 1] = current_dentry;
        }
        dentries_len += 1;
    }

    int j = 0;
    for (int i = dentries_len; i != 0; i--)
    {
        filepart_length = bpf_probe_read_kernel_str(dst->path_array[j], MAX_PATH, BPF_CORE_READ(dentries[i - 1], d_name.name));
        j = j + 1;
    }
    dst->patharray_len = j;
    return j;
}

#endif // EBPF_EVENTS_HELPERS_H
