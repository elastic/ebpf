// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

//
// eBPF common
//

#include "Common.h"

#include <argp.h>
#include <unistd.h>

struct ebpf_maps_info ebpf_maps[EBPF_MAP_NUM] = {
    {.type        = BPF_MAP_TYPE_HASH,
     .name        = EBPF_ALLOWED_IPS_MAP_NAME,
     .key_size    = sizeof(int),
     .value_size  = sizeof(int),
     .max_entries = 512,
     .map_flags   = 0},
    {.type        = BPF_MAP_TYPE_LPM_TRIE,
     .name        = EBPF_ALLOWED_SUBNETS_MAP_NAME,
     .key_size    = 8,
     .value_size  = sizeof(int),
     .max_entries = 256,
     .map_flags   = BPF_F_NO_PREALLOC},
    {.type        = BPF_MAP_TYPE_HASH,
     .name        = EBPF_ALLOWED_PIDS_MAP_NAME,
     .key_size    = sizeof(int),
     .value_size  = sizeof(int),
     .max_entries = 128,
     .map_flags   = 0},
};

// common log function
static libbpf_print_fn_t g_log_func = libbpf_print_fn;

int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    return vfprintf(stderr, format, args);
}

__attribute__((format(printf, 1, 2))) void ebpf_log(const char *format, ...)
{
    va_list args;

    if (!g_log_func)
        return;

    va_start(args, format);
    g_log_func(LIBBPF_WARN, format, args);
    va_end(args);
}

libbpf_print_fn_t ebpf_default_log_func()
{
    return libbpf_print_fn;
}

void ebpf_set_log_func(libbpf_print_fn_t fn)
{
    // set log function for this module
    g_log_func = fn;
    // set log function for libbpf
    libbpf_set_print(fn);
}
