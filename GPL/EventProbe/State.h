// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#ifndef EBPF_EVENTPROBE_EVENTS_STATE_H
#define EBPF_EVENTPROBE_EVENTS_STATE_H

enum ebpf_events_state_op {
    EBPF_EVENTS_STATE_UNKNOWN        = 0,
    EBPF_EVENTS_STATE_UNLINK         = 1,
    EBPF_EVENTS_STATE_RENAME         = 2,
    EBPF_EVENTS_STATE_TCP_V4_CONNECT = 3,
    EBPF_EVENTS_STATE_TCP_V6_CONNECT = 4,
};

struct ebpf_events_key {
    u64 pid_tgid;
    enum ebpf_events_state_op op;
} __attribute__((packed));

struct ebpf_events_unlink_state {
    struct vfsmount *mnt;
    struct dentry de;
};

enum ebpf_events_rename_state_step {
    RENAME_STATE_INIT      = 0,
    RENAME_STATE_MOUNT_SET = 1,
    RENAME_STATE_PATHS_SET = 2,
};

struct ebpf_events_rename_state {
    enum ebpf_events_rename_state_step step;
    struct vfsmount *mnt;
};

struct ebpf_events_tcp_connect_state {
    struct sock *sk;
};

struct ebpf_events_state {
    union {
        struct ebpf_events_unlink_state unlink;
        struct ebpf_events_rename_state rename;
        struct ebpf_events_tcp_connect_state tcp_v4_connect;
        struct ebpf_events_tcp_connect_state tcp_v6_connect;
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ebpf_events_key);
    __type(value, struct ebpf_events_state);
    __uint(max_entries, 4096);
} elastic_ebpf_events_state SEC(".maps");

static struct ebpf_events_key ebpf_events_state__key(enum ebpf_events_state_op op)
{
    struct ebpf_events_key key;
    key.pid_tgid = bpf_get_current_pid_tgid();
    key.op       = op;
    return key;
}

static struct ebpf_events_state *ebpf_events_state__get(enum ebpf_events_state_op op)
{
    struct ebpf_events_key key = ebpf_events_state__key(op);
    return bpf_map_lookup_elem(&elastic_ebpf_events_state, &key);
}

static long ebpf_events_state__set(enum ebpf_events_state_op op, struct ebpf_events_state *state)
{
    struct ebpf_events_key key = ebpf_events_state__key(op);
    return bpf_map_update_elem(&elastic_ebpf_events_state, &key, state, BPF_ANY);
}

#define PATH_MAX 4096
#define BUF PATH_MAX * 2

struct ebpf_events_rename_scratch_space {
    char old_path[BUF];
    char new_path[BUF];
};

struct ebpf_events_scratch_space {
    union {
        struct ebpf_events_rename_scratch_space rename;
    };
};

/* This map is only used to initialize a "ebpf_events_scratch_space" as
 * due to bpf stack size limitations, it can't be done in the program itself.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct ebpf_events_scratch_space);
    __uint(max_entries, 1);
} elastic_ebpf_events_init_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ebpf_events_key);
    __type(value, struct ebpf_events_scratch_space);
    __uint(max_entries, 512);
} elastic_ebpf_events_scratch_space SEC(".maps");

static struct ebpf_events_scratch_space *
ebpf_events_scratch_space__get(enum ebpf_events_state_op op)
{
    struct ebpf_events_key key = ebpf_events_state__key(op);
    return bpf_map_lookup_elem(&elastic_ebpf_events_scratch_space, &key);
}

static long ebpf_events_scratch_space__set(enum ebpf_events_state_op op,
                                           struct ebpf_events_scratch_space *ss)
{
    struct ebpf_events_key key = ebpf_events_state__key(op);
    return bpf_map_update_elem(&elastic_ebpf_events_scratch_space, &key, ss, BPF_ANY);
}

#endif // EBPF_EVENTPROBE_EVENTS_STATE_H
