// TODO:
// LICENSE
//
// Host Isolation standalone demo
// Loader for eBPF program #2 (attaches to tcp_v4_connect kprobe)
// 
#include <argp.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <sys/stat.h>

#include <Common.h>
#include "kprobe_loader.h"

struct bpf_object *
ebpf_open_object_file(const char *file_path)
{
    struct bpf_object *obj = NULL;

    if (!file_path)
    {
        ebpf_log("error: file path is NULL\n");
        obj = NULL;
        goto cleanup;
    }

    obj = bpf_object__open_file(file_path, NULL);
    if (!obj || libbpf_get_error(obj))
    {
        ebpf_log("failed to open BPF object\n");
        obj = NULL;
        goto cleanup;
    }

cleanup:
    return obj;
}

int
ebpf_map_set_pin_path(struct bpf_object *obj,
                      const char *map_name,
                      const char *map_path)
{
    struct bpf_map *map = NULL;
    int rv = 0;

    if (!obj || !map_name || !map_path)
    {
        ebpf_log("ebp_map_set_pin_path error: NULL parameter\n");
        rv = -1;
        goto cleanup;
    }

    map = bpf_object__find_map_by_name(obj, map_name);
    if (!map || libbpf_get_error(map))
    {
        ebpf_log("failed to load %s BPF map\n", map_name);
        rv = -1;
        goto cleanup;
    }

    rv = bpf_map__set_pin_path(map, map_path);
    if (rv)
    {
        ebpf_log("failed to set pin path for %s map\n", map_name);
        rv = -1;
        goto cleanup;
    }

cleanup:
    return rv;
}

struct bpf_link *
ebpf_load_and_attach_kprobe(struct bpf_object *obj,
                            const char *program_sec_name)
{
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    int prog_fd = -1;

    prog_fd = bpf_object__load(obj);
    if (prog_fd < 0)
    {
        ebpf_log("failed to load BPF program\n");
        link = NULL;
        goto cleanup;
    }

    prog = bpf_object__find_program_by_title(obj, program_sec_name);
    if (!prog || libbpf_get_error(prog))
    {
        ebpf_log("failed to find BPF program by name\n");
        link = NULL;
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if (!link || libbpf_get_error(link))
    {
        ebpf_log("failed to attach BPF program\n");
        link = NULL;
        goto cleanup;
    }

cleanup:
    return link;
}

void
ebpf_link_destroy(struct bpf_link *link)
{
    if (link)
    {
        bpf_link__destroy(link);
    }
}

void
ebpf_object_close(struct bpf_object *obj)
{
    if (obj)
    {
        bpf_object__close(obj);
    }
}
