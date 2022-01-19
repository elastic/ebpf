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

enum ebpf_fileevents_tid_state_id {
    EBPF_FILEEVENTS_TID_STATE_UNKNOWN = 0,
    EBPF_FILEEVENTS_TID_STATE_UNLINK  = 1,
};

struct ebpf_fileevents_unlink_state {
    struct vfsmount *mnt;
};
struct ebpf_fileevents_tid_state {
    enum ebpf_fileevents_tid_state_id state_id;
    union {
        struct ebpf_fileevents_unlink_state unlink;
    } state;
};

struct bpf_map_def SEC("maps") elastic_ebpf_fileevents_tid_state = {
    .type        = BPF_MAP_TYPE_LRU_HASH,
    .key_size    = sizeof(u64),
    .value_size  = sizeof(struct ebpf_fileevents_tid_state),
    .max_entries = 4096,
};

static __always_inline struct ebpf_fileevents_tid_state *ebpf_fileevents_write_state__get(void)
{
    u64 tid = bpf_get_current_pid_tgid();
    return bpf_map_lookup_elem(&elastic_ebpf_fileevents_tid_state, &tid);
}

static __always_inline long
ebpf_fileevents_write_state__set(struct ebpf_fileevents_tid_state *state)
{
    u64 tid = bpf_get_current_pid_tgid();
    return bpf_map_update_elem(&elastic_ebpf_fileevents_tid_state, &tid, state, BPF_ANY);
}
#endif // EBPF_EVENTPROBE_FILEEVENTS_HELPERS_H
