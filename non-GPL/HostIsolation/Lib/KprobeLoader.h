// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#ifndef EBPF_KPROBELOADER_H
#define EBPF_KPROBELOADER_H

#include "Common.h"

enum ebpf_load_method {
    EBPF_METHOD_NO_OVERRIDE = 0,
    EBPF_METHOD_VDSO,
    EBPF_METHOD_VERSION_H,
    EBPF_MAX_LOAD_METHODS,
};

/**
 * @brief Open eBPF object file
 *
 * @param[in] file_path Path to the eBPF object file
 * @returns eBPF object handle to be passed to other functions
 */
struct bpf_object *ebpf_open_object_file(const char *file_path);

/**
 * @brief Pin eBPF map by name and path
 *
 * @param[in] obj eBPF object handle
 * @param[in] map_name Name of the eBPF map (as in the bpf filesystem)
 * @param[in] map_path Path to the eBPF map in the bpf filesystem
 * @return Error value (0 for success)
 */
int ebpf_map_set_pin_path(struct bpf_object *obj, const char *map_name, const char *map_path);

/**
 * @brief Load and attach eBPF program to a kprobe
 *
 * @param[in] obj eBPF object handle
 * @param[in] program_name eBPF program name
 * @returns eBPF link handle to be passed to other functions
 */
struct bpf_link *ebpf_load_and_attach_kprobe(struct bpf_object *obj,
                                             const char *program_name,
                                             enum ebpf_load_method load_method);

#endif
