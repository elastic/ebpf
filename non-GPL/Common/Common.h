// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License 2.0;
 * you may not use this file except in compliance with the Elastic License 2.0.
 */

#ifndef EBPF_COMMON_H
#define EBPF_COMMON_H

#include <stdarg.h>

/* 
 *  matches libbpf_print_level defined in libbpf.h:
 *     enum libbpf_print_level {
 *             LIBBPF_WARN,
 *             LIBBPF_INFO,
 *             LIBBPF_DEBUG,
 *     };
 */
enum ebpf_print_level {
        EBPF_WARN,
        EBPF_INFO,
        EBPF_DEBUG,
};

/*
 *  matches libbpf_print_fn_t defined in libbpf.h:
 *     typedef int (*libbpf_print_fn_t)(enum libbpf_print_level level,
 *                   const char *, va_list ap);
 */
typedef int (*ebpf_print_fn_t)(enum ebpf_print_level level,
                 const char *, va_list ap);

void
ebpf_log(const char *format, ...);

void
ebpf_set_default_log_func();

void
ebpf_set_log_func(ebpf_print_fn_t fn);

#define EBPF_MAP_PARENT_DIRECTORY "/sys/fs/bpf/elastic"
#define EBPF_MAP_DIRECTORY "/sys/fs/bpf/elastic/endpoint"
#define EBPF_ALLOWED_IPS_MAP_NAME "allowed_IPs"
#define EBPF_ALLOWED_IPS_MAP_PATH "/sys/fs/bpf/elastic/endpoint/allowed_IPs"
#define EBPF_ALLOWED_PIDS_MAP_NAME "allowed_pids"
#define EBPF_ALLOWED_PIDS_MAP_PATH "/sys/fs/bpf/elastic/endpoint/allowed_pids"

#endif
