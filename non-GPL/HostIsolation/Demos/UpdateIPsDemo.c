// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

//
// Host Isolation - tool for updating maps of allowed IPs and subnets
//
#include <Common.h>
#include <argp.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <time.h>
#include <unistd.h>

#include "UpdateMaps.h"

int main(int argc, char **argv)
{
    int rv          = 0;
    uint32_t IPaddr = 0;
    char IP_str[64] = {0};
    char *str_ptr   = NULL;
    char *str_end   = NULL;
    long netmask    = 0;

    ebpf_set_log_func(ebpf_default_log_func());

    if (2 != argc) {
        printf("You need to pass an IPv4 address as an argument\n");
        rv = -1;
        goto cleanup;
    }

    str_ptr = strstr(argv[1], "/");
    if (str_ptr && (str_ptr[1] != '\0')) {
        /* An IP with subnet mask was given - add to allowed subnets map */
        memset(IP_str, 0, sizeof(IP_str));
        memcpy(IP_str, argv[1], (str_ptr - argv[1]));
        if (!inet_pton(AF_INET, IP_str, &IPaddr)) {
            printf("Error: given IP is invalid\n");
            rv = -1;
            goto cleanup;
        }

        str_ptr++;
        netmask = strtol(str_ptr, &str_end, 10);
        if (str_end == str_ptr || netmask > 32 || netmask < 0) {
            printf("Error parsing subnet mask\n");
            rv = -1;
            goto cleanup;
        }

        rv = ebpf_map_allowed_subnets_add(IPaddr, netmask);
        if (0 == rv) {
            printf("IP subnet %s added to " EBPF_ALLOWED_SUBNETS_MAP_NAME " BPF map!\n", argv[1]);
        }
    } else {
        if (!inet_pton(AF_INET, argv[1], &IPaddr)) {
            printf("Error: given IP is invalid\n");
            rv = -1;
            goto cleanup;
        }

        /* An IP with no subnet was given - add to allowed_IPs */
        rv = ebpf_map_allowed_IPs_add(IPaddr);
        if (0 == rv) {
            printf("IP %s added to " EBPF_ALLOWED_IPS_MAP_NAME " BPF map!\n", argv[1]);
        }
    }

cleanup:

    return rv;
}
