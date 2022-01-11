// SPDX-License-Identifier: GPL-2.0 OR LicenseRef-Elastic-License-2.0

/*
 * This file is dual-licensed under the GNU General Public License version 2
 * and the Elastic License 2.0. You may choose either one of them if you use
 * this file.
 */

#ifndef EBPF_EVENTPROBE_EBPFEVENTPROTO_H
#define EBPF_EVENTPROBE_EBPFEVENTPROTO_H

#define ARGV_MAX 8192 // See issue #43, quite possibly too small

#define PATH_MAX 4096

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

struct ebpf_event_header {
    uint64_t ts;
    uint64_t type;
} __attribute__((packed));

struct ebpf_file_path {
    uint32_t patharray_len;
    char path_array[MAX_PATH_DEPTH][MAX_PATH];
} __attribute__((packed));

struct ebpf_pid_info {
    uint32_t tgid;
    uint32_t sid;
} __attribute__((packed));

struct ebpf_tty_dev {
    uint16_t minor;
    uint16_t major;
} __attribute__((packed));

// Full events follow
struct ebpf_file_delete_event {
    struct ebpf_event_header hdr;

    struct ebpf_pid_info pids;
    struct ebpf_file_path path;
} __attribute__((packed));

struct ebpf_process_fork_event {
    struct ebpf_event_header hdr;

    struct ebpf_pid_info parent_pids;
    struct ebpf_pid_info child_pids;
} __attribute__((packed));

struct ebpf_process_exec_event {
    struct ebpf_event_header hdr;

    struct ebpf_pid_info pids;
    struct ebpf_tty_dev ctty;
    char filename[PATH_MAX];
    char cwd[PATH_MAX];
    char argv[ARGV_MAX];
} __attribute__((packed));

#endif // EBPF_EVENTPROBE_EBPFEVENTPROTO_H
