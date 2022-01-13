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

struct bpf_map_def SEC("maps") elastic_ebpf_fileevents_state = {
    .type        = BPF_MAP_TYPE_LRU_HASH,
    .key_size    = sizeof(struct ebpf_fileevents_key),
    .value_size  = sizeof(struct ebpf_fileevents_state),
    .max_entries = 4096,
};

static __always_inline struct ebpf_fileevents_key
ebpf_fileevents_state__key(enum ebpf_fileevents_state_op op)
{
    struct ebpf_fileevents_key key;
    key.pid_tgid = bpf_get_current_pid_tgid();
    key.op       = op;
    return key;
}

static __always_inline struct ebpf_fileevents_state *
ebpf_fileevents_state__get(enum ebpf_fileevents_state_op op)
{
    struct ebpf_fileevents_key key = ebpf_fileevents_state__key(op);
    return bpf_map_lookup_elem(&elastic_ebpf_fileevents_state, &key);
}

static __always_inline long ebpf_fileevents_state__set(enum ebpf_fileevents_state_op op,
                                                       struct ebpf_fileevents_state *state)
{
    struct ebpf_fileevents_key key = ebpf_fileevents_state__key(op);
    return bpf_map_update_elem(&elastic_ebpf_fileevents_state, &key, state, BPF_ANY);
}

#define PATH_MAX 4096
#define BUF PATH_MAX * 2

enum ebpf_fileevents_scratch_key {
    EBPF_FILEEVENTS_SCRATCH_KEY_RENAME = 0,
};

struct ebpf_fileevents_rename_scratch_state {
    char old_path[BUF];
    char new_path[BUF];
};

struct ebpf_fileevents_scratch_state {
    union {
        struct ebpf_fileevents_rename_scratch_state rename;
    };
};

/* Use a scratch map to store big objects as a state in
 * prog chains.
 *
 * https://git.kernel.org/pub/scm/linux/kernel/git/netdev/net.git/commit/?id=5722569bb9c3bd922c4f10b5b2912fe88c255312
 */
struct bpf_map_def SEC("maps") elastic_ebpf_fileevents_scratch_state = {
    .type        = BPF_MAP_TYPE_PERCPU_ARRAY,
    .key_size    = sizeof(enum ebpf_fileevents_scratch_key),
    .value_size  = sizeof(struct ebpf_fileevents_scratch_state),
    .max_entries = 1,
};

#endif // EBPF_EVENTPROBE_FILEEVENTS_HELPERS_H
