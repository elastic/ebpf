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

#ifndef EBPF_EVENTPROBE_FILEEVENTS_HELPERS_H
#define EBPF_EVENTPROBE_FILEEVENTS_HELPERS_H

enum ebpf_fileevents_state_op {
    EBPF_FILEEVENTS_STATE_UNKNOWN = 0,
    EBPF_FILEEVENTS_STATE_UNLINK  = 1,
    EBPF_FILEEVENTS_STATE_RENAME  = 2,
};

struct ebpf_fileevents_key {
    u64 pid_tgid;
    enum ebpf_fileevents_state_op op;
} __attribute__((packed));

struct ebpf_fileevents_unlink_state {
    struct vfsmount *mnt;
};

enum ebpf_fileevents_rename_state_step {
    RENAME_STATE_INIT      = 0,
    RENAME_STATE_MOUNT_SET = 1,
    RENAME_STATE_PATHS_SET = 2,
};

struct ebpf_fileevents_rename_state {
    enum ebpf_fileevents_rename_state_step step;
    struct vfsmount *mnt;
};

struct ebpf_fileevents_state {
    union {
        struct ebpf_fileevents_unlink_state unlink;
        struct ebpf_fileevents_rename_state rename;
    };
};

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ebpf_fileevents_key);
    __type(value, struct ebpf_fileevents_state);
    __uint(max_entries, 4096);
} elastic_ebpf_fileevents_state SEC(".maps");

static struct ebpf_fileevents_key ebpf_fileevents_state__key(enum ebpf_fileevents_state_op op)
{
    struct ebpf_fileevents_key key;
    key.pid_tgid = bpf_get_current_pid_tgid();
    key.op       = op;
    return key;
}

static struct ebpf_fileevents_state *ebpf_fileevents_state__get(enum ebpf_fileevents_state_op op)
{
    struct ebpf_fileevents_key key = ebpf_fileevents_state__key(op);
    return bpf_map_lookup_elem(&elastic_ebpf_fileevents_state, &key);
}

static long ebpf_fileevents_state__set(enum ebpf_fileevents_state_op op,
                                       struct ebpf_fileevents_state *state)
{
    struct ebpf_fileevents_key key = ebpf_fileevents_state__key(op);
    return bpf_map_update_elem(&elastic_ebpf_fileevents_state, &key, state, BPF_ANY);
}

#define PATH_MAX 4096
#define BUF PATH_MAX * 2

struct ebpf_fileevents_rename_scratch_space {
    char old_path[BUF];
    char new_path[BUF];
};

struct ebpf_fileevents_scratch_space {
    union {
        struct ebpf_fileevents_rename_scratch_space rename;
    };
};

/* This map is only used to initialize a "ebpf_fileevents_scratch_space" as
 * due to bpf stack size limitations, it can't be done in the program itself.
 */
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct ebpf_fileevents_scratch_space);
    __uint(max_entries, 1);
} elastic_ebpf_fileevents_init_buffer SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __type(key, struct ebpf_fileevents_key);
    __type(value, struct ebpf_fileevents_scratch_space);
    __uint(max_entries, 512);
} elastic_ebpf_fileevents_scratch_space SEC(".maps");

static struct ebpf_fileevents_scratch_space *
ebpf_fileevents_scratch_space__get(enum ebpf_fileevents_state_op op)
{
    struct ebpf_fileevents_key key = ebpf_fileevents_state__key(op);
    return bpf_map_lookup_elem(&elastic_ebpf_fileevents_scratch_space, &key);
}

static long ebpf_fileevents_scratch_space__set(enum ebpf_fileevents_state_op op,
                                               struct ebpf_fileevents_scratch_space *ss)
{
    struct ebpf_fileevents_key key = ebpf_fileevents_state__key(op);
    return bpf_map_update_elem(&elastic_ebpf_fileevents_scratch_space, &key, ss, BPF_ANY);
}

#endif // EBPF_EVENTPROBE_FILEEVENTS_HELPERS_H
