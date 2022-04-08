// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

//
// Host Isolation standalone demo
// Loader for eBPF program #2 (attaches to tcp_v4_connect kprobe)
//
#include <Common.h>
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/resource.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "KprobeLoader.h"

// try to load and attach an eBPF kprobe program with a specified load_method
static int try_load_ebpf_kprobe(const char *ebpf_file,
                                enum ebpf_load_method load_method,
                                struct bpf_object **bpf_obj,
                                struct bpf_link **bpf_link)
{
    struct bpf_object *obj = NULL;
    struct bpf_link *link  = NULL;
    int rv                 = 0;

    obj = ebpf_open_object_file(ebpf_file);
    if (!obj) {
        printf("failed to open BPF object\n");
        rv = -1;
        goto cleanup;
    }
    printf("BPF FILE OPENED\n");

    // pin allowed_IPs map when program is loaded
    rv = ebpf_map_set_pin_path(obj, EBPF_ALLOWED_IPS_MAP_NAME, EBPF_ALLOWED_IPS_MAP_PATH);
    if (rv) {
        printf("failed to init " EBPF_ALLOWED_IPS_MAP_NAME " BPF map\n");
        rv = -1;
        goto cleanup;
    }
    printf("BPF ALLOWED_IPS MAP LOADED\n");

    // pin allowed_pids map when program is loaded
    rv = ebpf_map_set_pin_path(obj, EBPF_ALLOWED_PIDS_MAP_NAME, EBPF_ALLOWED_PIDS_MAP_PATH);
    if (rv) {
        printf("failed to init " EBPF_ALLOWED_PIDS_MAP_NAME " BPF map\n");
        rv = -1;
        goto cleanup;
    }
    printf("BPF ALLOWED_PIDS MAP LOADED\n");

    // create elastic/endpoint dir in bpf fs
    if (mkdir(EBPF_MAP_PARENT_DIRECTORY, 0700) && errno != EEXIST) {
        printf("failed to create " EBPF_MAP_PARENT_DIRECTORY " dir, err=%d\n", errno);
        rv = -1;
        goto cleanup;
    }
    if (mkdir(EBPF_MAP_DIRECTORY, 0700) && errno != EEXIST) {
        printf("failed to create " EBPF_MAP_DIRECTORY " dir, err=%d\n", errno);
        rv = -1;
        goto cleanup;
    }

    link = ebpf_load_and_attach_kprobe(obj, "tcp_v4_connect", load_method);
    if (!link) {
        printf("failed to load and attach kprobe\n");
        rv = -1;
        goto cleanup;
    }
    printf("BPF PROGRAM ATTACHED TO KPROBE\n");

    rv = 0;

cleanup:
    if (rv) {
        bpf_object__close(obj);
        bpf_link__destroy(link);
    } else {
        *bpf_obj  = obj;
        *bpf_link = link;
    }
    return rv;
}

int main(int argc, char **argv)
{
    struct bpf_object *obj            = NULL;
    struct bpf_link *link             = NULL;
    enum ebpf_load_method load_method = EBPF_METHOD_NO_OVERRIDE;
    struct rlimit rl                  = {};
    int rv                            = -1;

    ebpf_set_log_func(ebpf_default_log_func());

    // increase locked memory rlimit to accommodate maps (which are treated as
    // locked memory)
    if (getrlimit(RLIMIT_MEMLOCK, &rl) == 0) {
        // set rlimit to 1MB
        rl.rlim_max = 1024 * 1024;
        rl.rlim_cur = rl.rlim_max;
        if (setrlimit(RLIMIT_MEMLOCK, &rl) != 0) {
            printf("setting rlimit failed! please run with sudo\n");
            rv = -1;
            goto cleanup;
        }
    } else {
        printf("setting rlimit failed! please run with sudo\n");
        rv = -1;
        goto cleanup;
    }

    // loading may fail on some older platforms - try all known methods
    rv = -1;
    while (rv && load_method < EBPF_MAX_LOAD_METHODS) {
        printf("trying loading method %d\n", load_method);
        rv = try_load_ebpf_kprobe("./KprobeConnectHook.bpf.o", load_method, &obj, &link);
        load_method++;
    }

    if (rv) {
        goto cleanup;
    }

    // eBPF program is detached by the kernel when process terminates
    // block until a signal arrives
    pause();

cleanup:
    // release libbpf resources
    bpf_object__close(obj);
    bpf_link__destroy(link);
    return rv;
}
