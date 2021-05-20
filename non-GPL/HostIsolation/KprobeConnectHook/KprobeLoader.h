// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License 2.0;
 * you may not use this file except in compliance with the Elastic License 2.0.
 */


#include <Common.h>

enum ebpf_load_method
{
    EBPF_METHOD_NO_OVERRIDE = 0,
    EBPF_METHOD_VDSO,
    EBPF_METHOD_VERSION_H,
    EBPF_MAX_LOAD_METHODS,
};

struct bpf_object *
ebpf_open_object_file(const char *file_path);

int
ebpf_map_set_pin_path(struct bpf_object *obj,
                      const char *map_name,
                      const char *map_path);
struct bpf_link *
ebpf_load_and_attach_kprobe(struct bpf_object *obj,
                            const char *program_sec_name,
                            enum ebpf_load_method load_method);

void
ebpf_link_destroy(struct bpf_link *link);

void
ebpf_object_close(struct bpf_object *obj);

