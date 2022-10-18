# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

# Copyright (C) 2021 Elasticsearch BV
#
# This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses, you
# may choose either one of them if you use this software.

ebpf_get_includes(LIBBPF_INCLUDES libbpf)

set(KPROBECONNECTHOOK_CFLAGS
    -g -O2
    -D__TARGET_ARCH_${ARCH_TRUNC}
    -D__${ARCH}__
    -I/usr/include
    ${LIBBPF_INCLUDES}
    -fno-ident)

ebpf_probe_target(KprobeConnectHook
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/KprobeConnectHook.bpf.c
    DEPENDENCIES libbpf vmlinux
    FLAGS ${KPROBECONNECTHOOK_CFLAGS}
    DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/KprobeConnectHook.bpf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/Kerneldefs.h
    GENSKELETON INSTALL
)
