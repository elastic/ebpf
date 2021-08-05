// SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License 2.0;
 * you may not use this file except in compliance with the Elastic License 2.0.
 */


//
// Host Isolation - tool for updating map of allowed IPs and pids
//
#include <argp.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <Common.h>
#include "UpdateMaps.h"

static int
ebpf_update_map(const char *map_path,
                uint32_t key,
                uint32_t val);

static int
ebpf_clear_map(const char *map_path);

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

int
ebpf_map_allowed_IPs_clear()
{
    return ebpf_clear_map(EBPF_ALLOWED_IPS_MAP_PATH);
}

int
ebpf_map_allowed_pids_clear()
{
    return ebpf_clear_map(EBPF_ALLOWED_PIDS_MAP_PATH);
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
        ebpf_log("Error: failed to add entry to map: %s, errno=%d\n", map_path, errno);
        goto cleanup;
    }

cleanup:
    if (map_fd >= 0)
    {
        close(map_fd);
    }

    return rv;
}

static int
ebpf_clear_map(const char *map_path)
{
    int rv = 0;
    int map_fd = -1;
    uint32_t key = -1;
    uint32_t next_key = -1;

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

    // get the first key
    if (bpf_map_get_next_key(map_fd, NULL, &key) < 0)
    {
        // map is already empty
        goto cleanup;
    }

    // iterate over map
    while (0 == bpf_map_get_next_key(map_fd, &key, &next_key))
    {
        // return value 0 means 'key' exists and 'next_key' has been set
        (void)bpf_map_delete_elem(map_fd, &key);
        key = next_key;
    }

    // -1 was returned so 'key' is the last element - delete it
    (void)bpf_map_delete_elem(map_fd, &key);

cleanup:
    if (map_fd >= 0)
    {
        close(map_fd);
    }

    return rv;
}
