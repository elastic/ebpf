// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License 2.0;
 * you may not use this file except in compliance with the Elastic License 2.0.
 */


//
// eBPF common
//

#include <argp.h>
#include <unistd.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include "Common.h"

static int
ebpf_print_fn(enum ebpf_print_level level,
              const char *format,
              va_list args);
static int
wrapper_print_fn(enum libbpf_print_level level,
                 const char *format,
                 va_list args);

// common log function and wrappers (needed to decouple clients from libbpf definitions)
static ebpf_print_fn_t g_ebpf_log_func = ebpf_print_fn;

// default log function - print to stderr
static int
ebpf_print_fn(enum ebpf_print_level level,
              const char *format,
              va_list args)
{
    return vfprintf(stderr, format, args);
}

// must match libbpf_print_fn_t signature defined in libbpf.h
static int
wrapper_print_fn(enum libbpf_print_level level,
                 const char *format,
                 va_list args)
{
    if (!g_ebpf_log_func)
    {
        return -1;
    }

    // convert libbpf_print_level to ebpf_print_level
    return g_ebpf_log_func((enum ebpf_print_level)level, format, args);
}

__attribute__((format(printf, 1, 2)))
void
ebpf_log(const char *format, ...)
{
    va_list args;

    if (!g_ebpf_log_func)
    {
        return;
    }

    va_start(args, format);
    g_ebpf_log_func(EBPF_WARN, format, args);
    va_end(args);
}

void
ebpf_set_default_log_func()
{
    // set log function for this module
    g_ebpf_log_func = ebpf_print_fn;
    // set log function for libbpf
    libbpf_set_print(wrapper_print_fn);
}

void
ebpf_set_log_func(ebpf_print_fn_t fn)
{
    // set log function for this module
    g_ebpf_log_func = fn;
    // set log function for libbpf
    libbpf_set_print(wrapper_print_fn);
}
