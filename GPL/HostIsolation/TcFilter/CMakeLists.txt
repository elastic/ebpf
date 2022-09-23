# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

# Copyright (C) 2021 Elasticsearch BV
#
# This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses, you
# may choose either one of them if you use this software.
ebpf_get_includes(LIBBPF_INCLUDES libbpf)
ebpf_get_includes(VMLINUX_INCLUDES vmlinux)

set(TCFILTER_CFLAGS
    -g -O2 -nostdinc -mcpu=v2
    -I${PROJECT_SOURCE_DIR}/contrib/kernel_hdrs
    -I${LIBBPF_INCLUDES}
    -D__KERNEL__
    -D__BPF_TRACING
    -Wno-unused-value
    -Wno-pointer-sign
    -Wno-compare-distinct-pointer-types
    -Wno-gnu-variable-sized-type-not-at-end
    -Wno-address-of-packed-member
    -Wno-tautological-compare
    -fno-asynchronous-unwind-tables
    -fno-stack-protector
    -fno-ident)


ebpf_probe_target(TcFilter
    SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/TcFilter.bpf.c
    DEPENDENCIES libbpf vmlinux
    FLAGS ${TCFILTER_CFLAGS}
    PUBLIC_HEADERS TcFilterdefs.h
    DEPENDS
    ${CMAKE_CURRENT_SOURCE_DIR}/TcFilter.bpf.c
    ${CMAKE_CURRENT_SOURCE_DIR}/TcFilterdefs.h
    ${CMAKE_CURRENT_SOURCE_DIR}/Kerneldefs.h
    GENSKELETON INSTALL
)

ebpf_gtest_binary(BPFTcFilterTests
    SOURCES BPFTcFilterTests.cpp
    LINK TcFilter libbpf
    INSTALL
)
