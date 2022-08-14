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

#include "KprobeLoader.h"

#include "Common.h"
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <elf.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

// requires glibc >= 2.16
//#define GETAUXVAL_SUPPORTED

#ifdef GETAUXVAL_SUPPORTED
#include <sys/auxv.h>
#endif

#if defined(__LP64__)
#define ElfW(type) Elf64_##type
#else
#define ElfW(type) Elf32_##type
#endif

static unsigned int find_version_note(unsigned long base)
{
    ElfW(Ehdr) *ehdr          = NULL;
    unsigned int version_code = 0;
    int i                     = 0;

    if (!base) {
        ebpf_log("find_version_note error: NULL parameter\n");
        goto out;
    }

    ehdr = (ElfW(Ehdr) *)base;

    for (i = 0; i < ehdr->e_shnum; i++) {
        ElfW(Shdr) *shdr = (ElfW(Shdr) *)(base + ehdr->e_shoff + (i * ehdr->e_shentsize));

        if (shdr->sh_type == SHT_NOTE) {
            const char *ptr = (const char *)(base + shdr->sh_offset);
            const char *end = ptr + shdr->sh_size;

            while (ptr < end) {
                ElfW(Nhdr) *nhdr = (ElfW(Nhdr) *)ptr;
                ptr += sizeof(*nhdr);

                const char *name = ptr;
                ptr += (nhdr->n_namesz + sizeof(ElfW(Word)) - 1) & -sizeof(ElfW(Word));

                const char *desc = ptr;
                ptr += (nhdr->n_descsz + sizeof(ElfW(Word)) - 1) & -sizeof(ElfW(Word));

                if ((nhdr->n_namesz > 5 && !memcmp(name, "Linux", 5)) && nhdr->n_descsz == 4 &&
                    !nhdr->n_type) {
                    version_code = *(uint32_t *)desc;
                    goto out;
                }
            }
        }
    }

out:
    return version_code;
}

static unsigned long get_auxiliary_vector_base(int at_key)
{
    unsigned long base = 0;

#ifdef GETAUXVAL_SUPPORTED
    base = getauxval(at_key);
    return base;
#else
    FILE *f = NULL;
    int err = 0;

    f = fopen("/proc/self/auxv", "r");
    if (!f) {
        err = -errno;
        ebpf_log("failed to open /proc/self/auxv: %d\n", err);
        return 0;
    }

    while (true) {
        unsigned long key   = 0;
        unsigned long value = 0;
        int ret             = -1;
        ret                 = fread(&key, sizeof(key), 1, f);
        if (ret != 1)
            break;
        ret = fread(&value, sizeof(value), 1, f);
        if (ret != 1)
            break;
        if (key == 0 && value == 0)
            break;
        if (key == at_key) {
            base = value;
            return base;
        }
    }
    return base;
#endif
}

static unsigned int get_kernel_version(enum ebpf_load_method method)
{
    unsigned int code = 0;
    int rv            = 0;
    FILE *f           = NULL;

    switch (method) {
    case EBPF_METHOD_NO_OVERRIDE: {
        // default method - do not override kernel version
        code = 0;
        goto out;
    }
    case EBPF_METHOD_VDSO: {
        // Fetch LINUX_VERSION_CODE from the vDSO .note section.
        // This always matches the running kernel, but is not supported on
        // arm32.
        unsigned long base = get_auxiliary_vector_base(AT_SYSINFO_EHDR);
        // Check ELF magic value
        if (base && !memcmp((void *)base, ELFMAG, 4)) {
            code = find_version_note(base);
        }
        goto out;
    }
    case EBPF_METHOD_VERSION_H: {
        // check if version.h exists
        f = fopen("/usr/include/linux/version.h", "r");
        if (!f) {
            code = 0;
            goto out;
        }
        rv = fscanf(f, "#define LINUX_VERSION_CODE %d", &code);
        if (rv != 1) {
            code = 0;
            fclose(f);
            goto out;
        }
        fclose(f);
        goto out;
    }
    default: {
        code = 0;
        goto out;
    }
    }

out:
    return code;
}

struct bpf_object *ebpf_open_object_file(const char *file_path)
{
    struct bpf_object *obj = NULL;

    if (!file_path) {
        ebpf_log("error: file path is NULL\n");
        obj = NULL;
        goto cleanup;
    }

    obj = bpf_object__open_file(file_path, NULL);
    if (!obj || libbpf_get_error(obj)) {
        ebpf_log("failed to open BPF object\n");
        bpf_object__close(obj);
        obj = NULL;
        goto cleanup;
    }

cleanup:
    return obj;
}

int ebpf_map_set_pin_path(struct bpf_object *obj, const char *map_name, const char *map_path)
{
    struct bpf_map *map = NULL;
    int rv              = 0;

    if (!obj || !map_name || !map_path) {
        ebpf_log("ebp_map_set_pin_path error: NULL parameter\n");
        rv = -1;
        goto cleanup;
    }

    map = bpf_object__find_map_by_name(obj, map_name);
    if (!map || libbpf_get_error(map)) {
        ebpf_log("failed to load %s BPF map\n", map_name);
        rv = -1;
        goto cleanup;
    }

    rv = bpf_map__set_pin_path(map, map_path);
    if (rv) {
        ebpf_log("failed to set pin path for %s map\n", map_name);
        rv = -1;
        goto cleanup;
    }

cleanup:
    return rv;
}

struct bpf_link *ebpf_load_and_attach_kprobe(struct bpf_object *obj,
                                             const char *program_name,
                                             enum ebpf_load_method load_method)
{
    struct bpf_program *prog    = NULL;
    struct bpf_link *link       = NULL;
    unsigned int kernel_version = 0;

    // Load may fail if an incorrect kernel version number was passed to the
    // bpf() syscall (old Linux kernels verify that, while newer kernels ignore
    // it). Try one of the methods of getting the kernel version, set it in
    // libbpf and load
    kernel_version = get_kernel_version(load_method);
    if (kernel_version != 0) {
        ebpf_log("got kernel_version=%d according to method=%d\n", kernel_version, load_method);
        if (bpf_object__set_kversion(obj, kernel_version) != 0) {
            ebpf_log("failed to set kversion\n");
        }
    }

    if (bpf_object__load(obj) < 0) {
        ebpf_log("failed to load BPF program\n");
        link = NULL;
        goto cleanup;
    }

    prog = bpf_object__find_program_by_name(obj, program_name);
    if (!prog || libbpf_get_error(prog)) {
        ebpf_log("failed to find BPF program by name\n");
        link = NULL;
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if (!link || libbpf_get_error(link)) {
        ebpf_log("failed to attach BPF program\n");
        bpf_link__destroy(link);
        link = NULL;
        goto cleanup;
    }

cleanup:
    return link;
}
