/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License 2.0;
 * you may not use this file except in compliance with the Elastic License 2.0.
 */


//
// Host Isolation - tool for updating map of allowed IPs
//
#include <argp.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#include <Common.h>
#include "UpdateMaps.h"

int
main(int argc,
     char **argv)
{
    int rv = 0;
    uint32_t IPaddr = 0;

    ebpf_set_log_func(ebpf_default_log_func());

    if (argc != 2)
    {
        printf("You need to pass an IPv4 address as an argument\n");
        rv = -1;
        goto cleanup;
    }


    if (!inet_pton(AF_INET, argv[1], &IPaddr))
    {
        printf("Error: given IP is invalid\n");
        rv = -1;
        goto cleanup;
    }

    rv = ebpf_map_allowed_IPs_add(IPaddr);

    if (rv == 0)
        printf("IP %s added to " EBPF_ALLOWED_IPS_MAP_NAME " BPF map!\n", argv[1]);

cleanup:

    return rv;
}

