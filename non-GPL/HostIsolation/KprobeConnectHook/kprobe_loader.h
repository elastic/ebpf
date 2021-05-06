#include <Common.h>

struct bpf_object *
ebpf_open_object_file(const char *file_path);

int
ebpf_map_set_pin_path(struct bpf_object *obj,
                      const char *map_name,
                      const char *map_path);
struct bpf_link *
ebpf_load_and_attach_kprobe(struct bpf_object *obj,
                            const char *program_sec_name);

void
ebpf_link_destroy(struct bpf_link *link);

void
ebpf_object_close(struct bpf_object *obj);

