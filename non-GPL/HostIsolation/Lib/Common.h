// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#ifndef EBPF_COMMON_H
#define EBPF_COMMON_H

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#define EBPF_MAP_PARENT_DIRECTORY "/sys/fs/bpf/elastic"
#define EBPF_MAP_DIRECTORY "/sys/fs/bpf/elastic/endpoint"
#define EBPF_ALLOWED_IPS_MAP_NAME "allowed_IPs"
#define EBPF_ALLOWED_IPS_MAP_PATH "/sys/fs/bpf/elastic/endpoint/allowed_IPs"
#define EBPF_ALLOWED_SUBNETS_MAP_NAME "allowed_subnets"
#define EBPF_ALLOWED_SUBNETS_MAP_PATH "/sys/fs/bpf/elastic/endpoint/allowed_subnets"
#define EBPF_ALLOWED_PIDS_MAP_NAME "allowed_pids"
#define EBPF_ALLOWED_PIDS_MAP_PATH "/sys/fs/bpf/elastic/endpoint/allowed_pids"

struct ebpf_maps_info {
    enum bpf_map_type type;
    const char *name;
    int key_size;
    int value_size;
    int max_entries;
    uint32_t map_flags;
};

enum ebpf_hostisolation_map {
    EBPF_MAP_ALLOWED_IPS = 0,
    EBPF_MAP_ALLOWED_SUBNETS,
    EBPF_MAP_ALLOWED_PIDS,
    EBPF_MAP_NUM
};

// ebpf map metadata
extern struct ebpf_maps_info ebpf_maps[EBPF_MAP_NUM];

/**
 * @brief Default libbpf log function
 *
 * @param[in] level Log level
 * @param[in] format Format string
 * @param[in] args Arguments to format string
 * @return
 */
int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);

/**
 * @brief Log function which is used by this eBPF library
 *
 * @param[in] format Format string
 * @param[in] args Arguments to format string
 */
void ebpf_log(const char *format, ...);

/**
 * @brief Returns the default log function used by the library
 * @return
 */
libbpf_print_fn_t ebpf_default_log_func();

/**
 * @brief Set a custom log function to be used by the eBPF library and libbpf
 * @param[in] fn Log function
 */
void ebpf_set_log_func(libbpf_print_fn_t fn);
#endif
