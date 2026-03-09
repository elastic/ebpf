// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

//
// Host Isolation standalone demo
// Loader for eBPF program #1 (replacement for 'tc filter add')
//
#include <Common.h>
#include <argp.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <fcntl.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

#include "TcLoader.h"
#include "TcFilter.skel.h"

int main(int argc, char **argv)
{
    struct netlink_ctx nl_ctx;
    struct bpf_program *prog = NULL;
    struct bpf_program *p    = NULL;
    struct TcFilter_bpf *ctx = NULL;
    struct bpf_map *map      = NULL;
    const char *map_name     = NULL;
    char buf[256]            = {0};
    int prog_fd_dupd         = 0;
    int rv                   = -1;
    const char *ifname       = NULL;
    bool unload_only         = false;

    memset(&nl_ctx, 0, sizeof(nl_ctx));

    if (argc < 2) {
        fprintf(stderr, "Usage: %s <interface> [unload]\n", argv[0]);
        return -1;
    }

    ifname = argv[1];
    if (argc >= 3) {
        if (!strcmp(argv[2], "unload")) {
            unload_only = true;
        } else {
            fprintf(stderr, "Unknown argument: %s\n", argv[2]);
            fprintf(stderr, "Usage: %s <interface> [unload]\n", argv[0]);
            return -1;
        }
    }
    if (argc > 3) {
        fprintf(stderr, "Too many arguments\n");
        fprintf(stderr, "Usage: %s <interface> [unload]\n", argv[0]);
        return -1;
    }

    /* do the same things as 'tc qdisc del dev <iface> clsact' */
    if (netlink_qdisc_del(ifname) != 0) {
        fprintf(stderr, "failed to del qdisc\n");
    } else {
        printf("DELETED QDISC (%s)\n", ifname);
    }

    /* if 'unload' is passed as arg, only delete qdisc */
    if (unload_only) {
        rv = 0;
        goto out;
    }

    /* 'tc qdisc add dev <iface> clsact' */
    if (netlink_qdisc_add(ifname) != 0) {
        fprintf(stderr, "failed to add qdisc\n");
        rv = -1;
        goto out;
    }

    printf("ADDED QDISC (%s)\n", ifname);

    /* 'tc filter add dev <iface> egress bpf da obj <ebpf_file> sec .text' */
    /* finished when netlink_filter_add_end() is called */
    if (netlink_filter_add_begin(&nl_ctx, ifname) != 0) {
        fprintf(stderr, "filter_add_begin() failed\n");
        rv = -1;
        goto out;
    }

    /* create elastic/endpoint dir in bpf fs */
    if (mkdir(EBPF_MAP_PARENT_DIRECTORY, 0700) && errno != EEXIST) {
        perror("failed to create directory: " EBPF_MAP_PARENT_DIRECTORY);
        rv = -1;
        goto out;
    }

    if (mkdir(EBPF_MAP_DIRECTORY, 0700) && errno != EEXIST) {
        perror("failed to create directory: " EBPF_MAP_DIRECTORY);
        rv = -1;
        goto out;
    }

    ebpf_set_log_func(ebpf_default_log_func());

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts, .relaxed_maps = true,
                        .pin_root_path = EBPF_MAP_DIRECTORY, );

    ctx = TcFilter_bpf__open_opts(&open_opts);
    if (!ctx || !ctx->obj || libbpf_get_error(ctx->obj)) {
        fprintf(stderr, "failed to open BPF skeleton\n");
        TcFilter_bpf__destroy(ctx);
        rv = -1;
        goto out;
    }
    printf("BPF SKELETON OPENED\n");

    bpf_object__for_each_program(p, ctx->obj)
    {
        bpf_program__set_type(p, BPF_PROG_TYPE_SCHED_CLS);
        bpf_program__set_ifindex(p, 0); //?
        if (!prog) {
            prog = p;
        }
    }
    bpf_object__for_each_map(map, ctx->obj)
    {
        bpf_map__set_ifindex(map, 0); //?
        map_name = bpf_map__name(map);
        if (map_name) {
            rv = snprintf(buf, sizeof(buf),
                          EBPF_MAP_DIRECTORY "/"
                                             "%s",
                          map_name);
            if (rv > 0) {
                bpf_map__set_pin_path(map, buf);
            }
        }
    }

    rv = TcFilter_bpf__load(ctx);
    if (rv) {
        fprintf(stderr, "failed to load BPF program\n");
        TcFilter_bpf__destroy(ctx);
        rv = -1;
        goto out;
    }
    printf("BPF PROG LOADED\n");

    prog_fd_dupd = fcntl(bpf_program__fd(prog), F_DUPFD_CLOEXEC, 1);
    if (prog_fd_dupd < 0) {
        perror("bad prog_fd_dupd");
        TcFilter_bpf__destroy(ctx);
        rv = -1;
        goto out;
    }

    TcFilter_bpf__destroy(ctx);
    ctx = NULL;

    /* tc filter add continued */
    if (netlink_filter_add_end(prog_fd_dupd, &nl_ctx) != 0) {
        fprintf(stderr, "filter_add_end() failed\n");
        close(prog_fd_dupd);
        rv = -1;
        goto out;
    }

    printf("BPF PROG ATTACHED TO TC\n");

    close(prog_fd_dupd);
    rv = 0;

out:
    return rv;
}
