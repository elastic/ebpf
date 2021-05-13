/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License 2.0;
 * you may not use this file except in compliance with the Elastic License 2.0.
 */


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
#include "KprobeLoader.h"

int
main(int argc,
     char **argv)
{
    struct bpf_object *obj = NULL;
    struct bpf_link *link = NULL;
    int rv = 0;

    ebpf_set_log_func(ebpf_default_log_func());

    obj = ebpf_open_object_file("./KprobeConnectHook.bpf.o");
    if (!obj)
    {
        printf("failed to open BPF object\n");
        rv = -1;
        goto cleanup;
    }
    printf("BPF FILE OPENED\n");

    // pin allowed_IPs map when program is loaded
    rv = ebpf_map_set_pin_path(obj, EBPF_ALLOWED_IPS_MAP_NAME, EBPF_ALLOWED_IPS_MAP_PATH);
    if (rv)
    {
        printf("failed to init " EBPF_ALLOWED_IPS_MAP_NAME " BPF map\n");
        rv = -1;
        goto cleanup;
    }
    printf("BPF ALLOWED_IPS MAP LOADED\n");

    // pin allowed_pids map when program is loaded
    rv = ebpf_map_set_pin_path(obj, EBPF_ALLOWED_PIDS_MAP_NAME, EBPF_ALLOWED_PIDS_MAP_PATH);
    if (rv)
    {
        printf("failed to init " EBPF_ALLOWED_PIDS_MAP_NAME " BPF map\n");
        rv = -1;
        goto cleanup;
    }
    printf("BPF ALLOWED_PIDS MAP LOADED\n");

    // create elastic/endpoint dir in bpf fs
    if (mkdir(EBPF_MAP_PARENT_DIRECTORY, 0700) && errno != EEXIST)
    {
        printf("failed to create " EBPF_MAP_PARENT_DIRECTORY " dir, err=%d\n", errno);
        rv = -1;
        goto cleanup;
    }
    if (mkdir(EBPF_MAP_DIRECTORY, 0700) && errno != EEXIST)
    {
        printf("failed to create " EBPF_MAP_DIRECTORY " dir, err=%d\n", errno);
        rv = -1;
        goto cleanup;
    }

    link = ebpf_load_and_attach_kprobe(obj, "kprobe/tcp_v4_connect");
    if (!link)
    {
        printf("failed to load and attach kprobe\n");
        rv = -1;
        goto cleanup;
    }
    printf("BPF PROGRAM ATTACHED TO KPROBE\n");

    // eBPF program is detached by the kernel when process terminates
    // sleep forever
    pause();

cleanup:
    if (link)
    {
        ebpf_link_destroy(link);
    }
    if (obj)
    {
        ebpf_object_close(obj);
    }

    return rv;
}
