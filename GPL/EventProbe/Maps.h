#ifndef EBPF_EVENTPROBE_MAPS_H
#define EBPF_EVENTPROBE_MAPS_H

// todo(fntlnz): another buffer will probably need
// to be used instead of this one as the common parts evolve
// to have a shared buffer between File, Network and Process.
struct bpf_map_def SEC("maps") ringbuf = {
    .type        = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 4096 * 64, // todo: Need to verify if 256 kb is what we want
};

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

#endif // EBPF_EVENTPROBE_MAPS_H
