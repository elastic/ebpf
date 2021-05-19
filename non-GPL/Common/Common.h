// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License 2.0;
 * you may not use this file except in compliance with the Elastic License 2.0.
 */


#include <bpf/bpf.h>
#include <bpf/libbpf.h>

int
libbpf_print_fn(enum libbpf_print_level level,
                const char *format,
                va_list args);

void
ebpf_log(const char *format, ...);

libbpf_print_fn_t
ebpf_default_log_func();

void
ebpf_set_log_func(libbpf_print_fn_t fn);

#define EBPF_MAP_PARENT_DIRECTORY "/sys/fs/bpf/elastic"
#define EBPF_MAP_DIRECTORY "/sys/fs/bpf/elastic/endpoint"
#define EBPF_ALLOWED_IPS_MAP_NAME "allowed_IPs"
#define EBPF_ALLOWED_IPS_MAP_PATH "/sys/fs/bpf/elastic/endpoint/allowed_IPs"
#define EBPF_ALLOWED_PIDS_MAP_NAME "allowed_pids"
#define EBPF_ALLOWED_PIDS_MAP_PATH "/sys/fs/bpf/elastic/endpoint/allowed_pids"

