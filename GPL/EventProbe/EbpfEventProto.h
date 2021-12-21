// SPDX-License-Identifier: GPL-2.0 OR LicenseRef-Elastic-License-2.0

/*
 * This file is dual-licensed under the GNU General Public License version 2
 * and the Elastic License 2.0. You may choose either one of them if you use
 * this file.
 */

#ifndef EBPF_EVENTPROBE_EBPFEVENTPROTO_H
#define EBPF_EVENTPROBE_EBPFEVENTPROTO_H

#define MAX_PATH_DEPTH 32
#define MAX_PATH 256
#define MAX_FILEPATH_LENGTH (MAX_PATH_DEPTH * MAX_PATH)

#ifndef __KERNEL__
#include <stdint.h>
#else
#include "vmlinux.h"
#endif

enum ebpf_event_type {
    EBPF_EVENT_PROCESS_FORK = (1 << 1),
    EBPF_EVENT_PROCESS_EXEC = (1 << 2),
    EBPF_EVENT_FILE_DELETE  = (1 << 3),
};

struct ebpf_event {
    uint64_t ts;
    uint64_t type;
    char data[];
} __attribute__((packed));

struct ebpf_event_file_path {
    uint32_t patharray_len;
    char path_array[MAX_PATH_DEPTH][MAX_PATH];
} __attribute__((packed));

struct ebpf_event_file_delete_data {
    uint32_t pid;
    struct ebpf_event_file_path path;
} __attribute__((packed));

struct ebpf_event_process_fork_data {
    uint32_t parent_pid;
    uint32_t child_pid;
} __attribute__((packed));

struct ebpf_event_process_exec_data {
    uint32_t pid;
} __attribute__((packed));

#endif // EBPF_EVENTPROBE_EBPFEVENTPROTO_H
