// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#ifndef EBPF_EVENTPROBE_EBPFEVENTPROTO_H
#define EBPF_EVENTPROBE_EBPFEVENTPROTO_H

#define TASK_COMM_LEN 16

#ifndef __KERNEL__
#include <stdint.h>
#else
#include "vmlinux.h"
#endif

enum ebpf_event_type {
    EBPF_EVENT_PROCESS_FORK                 = (1 << 1),
    EBPF_EVENT_PROCESS_EXEC                 = (1 << 2),
    EBPF_EVENT_PROCESS_EXIT                 = (1 << 3),
    EBPF_EVENT_PROCESS_SETSID               = (1 << 4),
    EBPF_EVENT_PROCESS_SETUID               = (1 << 5),
    EBPF_EVENT_PROCESS_SETGID               = (1 << 6),
    EBPF_EVENT_PROCESS_TTY_WRITE            = (1 << 7),
    EBPF_EVENT_FILE_DELETE                  = (1 << 8),
    EBPF_EVENT_FILE_CREATE                  = (1 << 9),
    EBPF_EVENT_FILE_RENAME                  = (1 << 10),
    EBPF_EVENT_FILE_MODIFY                  = (1 << 11),
    EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED  = (1 << 12),
    EBPF_EVENT_NETWORK_CONNECTION_ATTEMPTED = (1 << 13),
    EBPF_EVENT_NETWORK_CONNECTION_CLOSED    = (1 << 14),
};

struct ebpf_event_header {
    uint64_t ts;
    uint64_t type;
} __attribute__((packed));

// Some fields passed up (e.g. argv, path names) have a high maximum size but
// most instances of them won't come close to hitting the maximum. Instead of
// wasting a huge amount of memory by using a fixed-size buffer that's the
// maximum possible size, we pack these fields into variable-length buffers at
// the end of each event. If a new field to be added has a large maximum size
// that won't often be reached, it should be added as a variable length field.
enum ebpf_varlen_field_type {
    EBPF_VL_FIELD_CWD,
    EBPF_VL_FIELD_ARGV,
    EBPF_VL_FIELD_ENV,
    EBPF_VL_FIELD_FILENAME,
    EBPF_VL_FIELD_PATH,
    EBPF_VL_FIELD_OLD_PATH,
    EBPF_VL_FIELD_NEW_PATH,
    EBPF_VL_FIELD_TTY_OUT,
    EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH,
    EBPF_VL_FIELD_SYMLINK_TARGET_PATH,
};

// Convenience macro to iterate all the variable length fields in an event
#define FOR_EACH_VARLEN_FIELD(vl_fields_start, cursor)                                             \
    uint32_t __i = 0;                                                                              \
    cursor       = (struct ebpf_varlen_field *)vl_fields_start.data;                               \
    for (; __i < vl_fields_start.nfields;                                                          \
         cursor = (struct ebpf_varlen_field *)((char *)cursor + cursor->size +                     \
                                               sizeof(struct ebpf_varlen_field)),                  \
         __i++)

struct ebpf_varlen_fields_start {
    uint32_t nfields;
    size_t size;
    char data[];
} __attribute__((packed));

struct ebpf_varlen_field {
    enum ebpf_varlen_field_type type;
    uint32_t size;
    char data[];
} __attribute__((packed));

struct ebpf_pid_info {
    uint64_t start_time_ns;
    uint32_t tid;
    uint32_t tgid;
    uint32_t ppid;
    uint32_t pgid;
    uint32_t sid;
} __attribute__((packed));

struct ebpf_cred_info {
    uint32_t ruid; // Real user ID
    uint32_t rgid; // Real group ID
    uint32_t euid; // Effective user ID
    uint32_t egid; // Effective group ID
    uint32_t suid; // Saved user ID
    uint32_t sgid; // Saved group ID
    uint64_t cap_permitted;
    uint64_t cap_effective;
} __attribute__((packed));

struct ebpf_tty_winsize {
    uint16_t rows;
    uint16_t cols;
} __attribute__((packed));

struct ebpf_tty_termios {
    uint32_t c_iflag;
    uint32_t c_oflag;
    uint32_t c_lflag;
    uint32_t c_cflag;
} __attribute__((packed));

struct ebpf_tty_dev {
    uint16_t minor;
    uint16_t major;
    struct ebpf_tty_winsize winsize;
    struct ebpf_tty_termios termios;
} __attribute__((packed));

enum ebpf_file_type {
    EBPF_FILE_TYPE_UNKNOWN          = 0,
    EBPF_FILE_TYPE_FILE             = 1,
    EBPF_FILE_TYPE_DIR              = 2,
    EBPF_FILE_TYPE_SYMLINK          = 3,
    EBPF_FILE_TYPE_CHARACTER_DEVICE = 4,
    EBPF_FILE_TYPE_BLOCK_DEVICE     = 5,
    EBPF_FILE_TYPE_NAMED_PIPE       = 6,
    EBPF_FILE_TYPE_SOCKET           = 7,
};

struct ebpf_file_info {
    enum ebpf_file_type type;
    uint64_t inode;
    uint16_t mode;
    uint64_t size;
    uint32_t uid;
    uint32_t gid;
    uint64_t atime;
    uint64_t mtime;
    uint64_t ctime;
} __attribute__((packed));

// Full events follow
struct ebpf_file_delete_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    struct ebpf_file_info finfo;
    uint32_t mntns;
    char comm[TASK_COMM_LEN];

    // Variable length fields: path, symlink_target_path
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

struct ebpf_file_create_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    struct ebpf_file_info finfo;
    uint32_t mntns;
    char comm[TASK_COMM_LEN];

    // Variable length fields: path, symlink_target_path
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

struct ebpf_file_rename_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    struct ebpf_file_info finfo;
    uint32_t mntns;
    char comm[TASK_COMM_LEN];

    // Variable length fields: old_path, new_path, symlink_target_path
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

enum ebpf_file_change_type {
    EBPF_FILE_CHANGE_TYPE_UNKNOWN     = 0,
    EBPF_FILE_CHANGE_TYPE_CONTENT     = 1,
    EBPF_FILE_CHANGE_TYPE_PERMISSIONS = 2,
    EBPF_FILE_CHANGE_TYPE_OWNER       = 3,
    EBPF_FILE_CHANGE_TYPE_XATTRS      = 4,
};

struct ebpf_file_modify_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    struct ebpf_file_info finfo;
    enum ebpf_file_change_type change_type;
    uint32_t mntns;
    char comm[TASK_COMM_LEN];

    // Variable length fields: path, symlink_target_path
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

struct ebpf_process_fork_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info parent_pids;
    struct ebpf_pid_info child_pids;
    struct ebpf_cred_info creds;

    // Variable length fields: pids_ss_cgroup_path
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

struct ebpf_process_exec_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    struct ebpf_cred_info creds;
    struct ebpf_tty_dev ctty;

    // Variable length fields: cwd, argv, env, filename, pids_ss_cgroup_path
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

struct ebpf_process_exit_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    int32_t exit_code;

    // Variable length fields: pids_ss_cgroup_path
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

struct ebpf_process_setsid_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
} __attribute__((packed));

struct ebpf_process_setuid_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    uint32_t new_ruid;
    uint32_t new_euid;
    uint32_t new_rgid;
    uint32_t new_egid;
} __attribute__((packed));

struct ebpf_process_tty_write_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    uint64_t tty_out_truncated;

    // Controlling TTY.
    struct ebpf_tty_dev ctty;

    // Destination TTY.
    struct ebpf_tty_dev tty;
    char comm[TASK_COMM_LEN];

    // Variable length fields: tty_out
    struct ebpf_varlen_fields_start vl_fields;
} __attribute__((packed));

struct ebpf_process_setgid_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    uint32_t new_rgid;
    uint32_t new_egid;
    uint32_t new_ruid;
    uint32_t new_euid;
} __attribute__((packed));

enum ebpf_net_info_transport {
    EBPF_NETWORK_EVENT_TRANSPORT_TCP = 1,
};

enum ebpf_net_info_af {
    EBPF_NETWORK_EVENT_AF_INET  = 1,
    EBPF_NETWORK_EVENT_AF_INET6 = 2,
};

struct ebpf_net_info_tcp_close {
    uint64_t bytes_sent;
    uint64_t bytes_received;
} __attribute__((packed));

struct ebpf_net_info {
    enum ebpf_net_info_transport transport;
    enum ebpf_net_info_af family;
    union {
        uint8_t saddr[4];
        uint8_t saddr6[16];
    }; // Network byte order
    union {
        uint8_t daddr[4];
        uint8_t daddr6[16];
    };              // Network byte order
    uint16_t sport; // Host byte order
    uint16_t dport; // Host byte order
    uint32_t netns;
    union {
        struct ebpf_net_info_tcp_close close;
    } tcp;
} __attribute__((packed));

struct ebpf_net_event {
    struct ebpf_event_header hdr;
    struct ebpf_pid_info pids;
    struct ebpf_net_info net;
    char comm[TASK_COMM_LEN];
} __attribute__((packed));

#endif // EBPF_EVENTPROBE_EBPFEVENTPROTO_H
