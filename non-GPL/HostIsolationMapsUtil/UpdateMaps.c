// SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License 2.0;
 * you may not use this file except in compliance with the Elastic License 2.0.
 */


//
// Host Isolation - tool for updating maps of allowed IPs, subnets and pids
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
                enum ebpf_hostisolation_map map_id,
                const void *key,
                const void *val);
static int
ebpf_create_map(enum ebpf_hostisolation_map map_id,
                int *map_fd);
static int
ebpf_clear_map(const char *map_path,
                enum ebpf_hostisolation_map map_id);

int
ebpf_map_allowed_IPs_add(uint32_t IPaddr)
{
    uint32_t key = IPaddr;
    uint32_t val = 1;   // values are not used in the hash map

    return ebpf_update_map(EBPF_ALLOWED_IPS_MAP_PATH, EBPF_MAP_ALLOWED_IPS, &key, &val);
}

int
ebpf_map_allowed_subnets_add(uint32_t IPaddr, uint32_t netmask)
{
    struct lpm_key
    {
        uint32_t prefix;
        uint32_t IP;
    } key =
    {
        .prefix = netmask,
        .IP = IPaddr,
    };
    uint32_t val = 1;   // values are not used in the lpm trie map

    return ebpf_update_map(EBPF_ALLOWED_SUBNETS_MAP_PATH, EBPF_MAP_ALLOWED_SUBNETS, &key, &val);
}

int
ebpf_map_allowed_pids_add(uint32_t pid)
{
    uint32_t key = pid;
    uint32_t val = 1;   // values are not used in the hash map

    return ebpf_update_map(EBPF_ALLOWED_PIDS_MAP_PATH, EBPF_MAP_ALLOWED_PIDS, &key, &val);
}

int
ebpf_map_allowed_IPs_clear()
{
    return ebpf_clear_map(EBPF_ALLOWED_IPS_MAP_PATH, EBPF_MAP_ALLOWED_IPS);
}

int
ebpf_map_allowed_subnets_clear()
{
    return ebpf_clear_map(EBPF_ALLOWED_SUBNETS_MAP_PATH, EBPF_MAP_ALLOWED_SUBNETS);
}

int
ebpf_map_allowed_pids_clear()
{
    return ebpf_clear_map(EBPF_ALLOWED_PIDS_MAP_PATH, EBPF_MAP_ALLOWED_PIDS);
}

static int
ebpf_create_map(enum ebpf_hostisolation_map map_id,
                int *map_fd)
{
    int rv = 0;
    int fd = -1;

    if (map_id >= EBPF_MAP_NUM)
    {
        ebpf_log("Error: invalid map ID\n");
        rv = -1;
        goto cleanup;
    }

    fd = bpf_create_map_name(ebpf_maps[map_id].type,
                             ebpf_maps[map_id].name,
                             ebpf_maps[map_id].key_size,
                             ebpf_maps[map_id].value_size,
                             ebpf_maps[map_id].max_entries,
                             ebpf_maps[map_id].map_flags);

    if (fd < 0)
    {
        ebpf_log("Error creating map\n");
        rv = -1;
        goto cleanup;
    }

    *map_fd = fd;

cleanup:
    return rv;
}

static int
ebpf_update_map(const char *map_path, enum ebpf_hostisolation_map map_id, const void *key, const void *val)
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
        // perhaps the map does not exist, try to create it and pin to bpf fs
        rv = ebpf_create_map(map_id, &map_fd);
        if (rv)
        {
            ebpf_log("Error updating map, make sure to run with sudo. Errno=%d\n", errno);
            goto cleanup;
        }
        rv = bpf_obj_pin(map_fd, map_path);
        if (rv)
        {
            ebpf_log("Error pinning map, make sure to run with sudo. Errno=%d\n", errno);
            goto cleanup;
        }
    }

    rv = bpf_map_update_elem(map_fd, key, val, 0);
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
ebpf_clear_map(const char *map_path,
               enum ebpf_hostisolation_map map_id)
{
    int rv = 0;
    int map_fd = -1;
    uint8_t key_buf[64] = {0};
    uint8_t next_key_buf[64] = {0};

    if (map_path == NULL)
    {
        ebpf_log("Error: map_path is NULL\n");
        rv = -1;
        goto cleanup;
    }

    map_fd = bpf_obj_get(map_path);
    if (map_fd < 0)
    {
        // perhaps the map does not exist, try to create it
        rv = ebpf_create_map(map_id, &map_fd);
        if (rv)
        {
            ebpf_log("Error clearing map, make sure to run with sudo. Errno=%d\n", errno);
            goto cleanup;
        }
    }

    // get the first key
    if (bpf_map_get_next_key(map_fd, NULL, key_buf) < 0)
    {
        // map is already empty
        goto cleanup;
    }

    // iterate over map
    while (0 == bpf_map_get_next_key(map_fd, key_buf, next_key_buf))
    {
        // return value 0 means 'key' exists and 'next_key' has been set
        (void)bpf_map_delete_elem(map_fd, key_buf);
	memcpy(key_buf, next_key_buf, sizeof(key_buf));
    }

    // -1 was returned so 'key' is the last element - delete it
    (void)bpf_map_delete_elem(map_fd, key_buf);

cleanup:
    if (map_fd >= 0)
    {
        close(map_fd);
    }

    return rv;
}
