#ifndef EBPF_EVENTS_MAPS_H
#define EBPF_EVENTS_MAPS_H

// todo(fntlnz): another buffer will probably need
// to be used instead of this one as the common parts evolve
// to have a shared buffer between File, Network and Process.
struct bpf_map_def SEC("maps") elastic_ebpf_events_buffer = {
    .type = BPF_MAP_TYPE_RINGBUF,
    .max_entries = 4096 * 64, // todo: Need to verify if 256 kb is what we want
};

#endif // EBPF_EVENTS_MAPS_H
