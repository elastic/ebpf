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

#ifndef EBPF_EVENTS_FILEEVENTS_H
#define EBPF_EVENTS_FILEEVENTS_H

#ifdef __KERNEL__
#include <bpf/bpf_core_read.h>
#endif

// todo(fntlnz): anywhere we can take this from?
#define PATH_MAX 4096

struct ebpf_event_file_delete_data
{
    __u32 pid;
    int dfd;
    char name[PATH_MAX];
};

#ifdef __KERNEL__

static __always_inline void ebpf_event_file_delete_data__set_pid(struct ebpf_event_file_delete_data *event, __u32 pid)
{
    event->pid = pid;
}

static __always_inline void ebpf_event_file_delete_data__set_dfd(struct ebpf_event_file_delete_data *event, int dfd)
{
    event->dfd = dfd;
}

static __always_inline void ebpf_event_file_delete_data__set_name(struct ebpf_event_file_delete_data *event, struct filename *name)
{
    bpf_core_read_str(event->name, PATH_MAX, name->name);
}

#endif // ifdef __KERNEL__
#endif // EBPF_EVENTS_FILEEVENTS_H
