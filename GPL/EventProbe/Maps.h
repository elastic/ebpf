#ifndef EBPF_EVENTPROBE_MAPS_H
#define EBPF_EVENTPROBE_MAPS_H

// todo(fntlnz): another buffer will probably need
// to be used instead of this one as the common parts evolve
// to have a shared buffer between File, Network and Process.
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 4096 * 64); // todo: Need to verify if 256 kb is what we want
} ringbuf SEC(".maps");

#endif // EBPF_EVENTPROBE_MAPS_H
