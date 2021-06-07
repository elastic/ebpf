// TODO:
// LICENSE
//
// Host Isolation - tool for updating map of allowed IPs and pids
//
#include <argp.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#include <Common.h>
#include "UpdateMaps.h"

static int
ebpf_update_map(const char *map_path,
                uint32_t key,
                uint32_t val);

int
ebpf_map_allowed_IPs_add(uint32_t IPaddr)
{
    uint32_t key = IPaddr;
    uint32_t val = 1;   // values are not used in the hash map

    return ebpf_update_map(EBPF_ALLOWED_IPS_MAP_PATH, key, val);
}

int
ebpf_map_allowed_pids_add(uint32_t pid)
{
    uint32_t key = pid;
    uint32_t val = 1;   // values are not used in the hash map

    return ebpf_update_map(EBPF_ALLOWED_PIDS_MAP_PATH, key, val);
}

static int
ebpf_update_map(const char *map_path, uint32_t key, uint32_t val)
{
    int rv = 0;
    int map_fd = -1;

    if (map_path == NULL)
    {
        ebpf_log("Error: map_path is NULL\n");
        rv = -1;
        goto cleanup;
    }

    map_fd = bpf_obj_get(map_path);
    if (map_fd < 0)
    {
        ebpf_log("Error: run with sudo or make sure %s exists\n", map_path);
        rv = -1;
        goto cleanup;
    }

    rv = bpf_map_update_elem(map_fd, &key, &val, 0);
    if (rv)
    {
        ebpf_log("Error: failed to add entry to map: %s \n", map_path);
        goto cleanup;
    }

cleanup:
    if (map_fd >= 0)
    {
        close(map_fd);
    }

    return rv;
}
