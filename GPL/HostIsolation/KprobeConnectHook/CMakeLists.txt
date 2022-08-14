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

set(KPROBECONNECTHOOK_BPF_OUTPUT ${HOSTISOLATION_EBPF_OBJECT_DIR}/KprobeConnectHook.bpf.o)
set(KPROBECONNECTHOOK_BPF_SKELETON_PATH ${HOSTISOLATION_EBPF_OBJECT_DIR}/KprobeConnectHook.skel.h)

ebpf_probe_target(BPFKprobeConnectHook
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/KprobeConnectHook.bpf.c
    DEPENDENCIES libbpf vmlinux
    FLAGS ${KPROBECONNECTHOOK_CFLAGS}
    GENSKELETON INSTALL
)