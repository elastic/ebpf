# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

# Copyright (C) 2021 Elasticsearch BV
#
# This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses, you
# may choose either one of them if you use this software.

ebpf_get_includes(LIBBPF_INCLUDES libbpf)
ebpf_get_includes(VMLINUX_INCLUDES vmlinux)

if (CMAKE_BUILD_TYPE STREQUAL Debug OR ENABLE_BPF_PRINTK)
    set(BPF_DEBUG_TRACE 1)
else()
    set(BPF_DEBUG_TRACE 0)
endif()

set(EVENTS_PROBE_CFLAGS
    -g -O2
    ${LIBBPF_INCLUDES} ${VMLINUX_INCLUDES}
    -D__KERNEL__
    -DBPF_DEBUG_TRACE=${BPF_DEBUG_TRACE}
    -D__TARGET_ARCH_${ARCH_TRUNC}
    -D__${ARCH}__
    -I${CMAKE_CURRENT_SOURCE_DIR}
    -fno-ident
)

ebpf_probe_target(EventProbe
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/EventProbe.bpf.c
    DEPENDENCIES libbpf vmlinux
    FLAGS ${EVENTS_PROBE_CFLAGS}
    PUBLIC_HEADERS EbpfEventProto.h
    DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/File/Probe.bpf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/Network/Probe.bpf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/Network/Network.h
    ${CMAKE_CURRENT_SOURCE_DIR}/Process/Probe.bpf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/EbpfEventProto.h
    ${CMAKE_CURRENT_SOURCE_DIR}/EventProbe.bpf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/Helpers.h
    ${CMAKE_CURRENT_SOURCE_DIR}/PathResolver.h
    ${CMAKE_CURRENT_SOURCE_DIR}/State.h
    GENSKELETON INSTALL
)
