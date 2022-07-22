# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

# Copyright (C) 2021 Elasticsearch BV
#
# This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses, you
# may choose either one of them if you use this software.

if (CMAKE_BUILD_TYPE STREQUAL Debug OR ENABLE_BPF_PRINTK)
    set(BPF_DEBUG_TRACE 1)
else()
    set(BPF_DEBUG_TRACE 0)
endif()

set(EVENTS_PROBE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(EVENTS_PROBE_DEPFILE ${CMAKE_CURRENT_BINARY_DIR}/EventProbe.bpf.d)
set(EVENTS_PROBE_CFLAGS
                -g -O2
                -target bpf
                -MD -MF ${EVENTS_PROBE_DEPFILE}
                -D__KERNEL__
                -DBPF_DEBUG_TRACE=${BPF_DEBUG_TRACE}
                -D__TARGET_ARCH_${ARCH_TRUNC}
                -D__${ARCH}__
                -I${LIBBPF_TARGET_INCLUDE_DIR}
                -I${VMLINUX_INCLUDE_DIR}
                -I${EVENTS_PROBE_SOURCE_DIR}
                -fno-ident)

set(EVENTS_PROBE_SOURCES ${EVENTS_PROBE_SOURCE_DIR}/EventProbe.bpf.c)
file(GLOB EVENTS_PROBE_INCLUDES "${EVENTS_PROBE_SOURCE_DIR}/*.h")

set(EVENTS_PROBE_BPF_OUTPUT ${CMAKE_CURRENT_BINARY_DIR}/EventProbe.bpf.o)
add_custom_command(OUTPUT ${EVENTS_PROBE_BPF_OUTPUT}
                  COMMAND ${EBPF_EXTERNAL_ENV_FLAGS} ${CLANG} ${EVENTS_PROBE_CFLAGS} -c ${EVENTS_PROBE_SOURCES} -o ${EVENTS_PROBE_BPF_OUTPUT}
                  DEPENDS libbpf
                  DEPFILE ${EVENTS_PROBE_DEPFILE})

add_custom_target(BPFEventProbe ALL DEPENDS ${EVENTS_PROBE_BPF_OUTPUT})

if (NOT CMAKE_BUILD_TYPE STREQUAL Debug)
    add_custom_command(TARGET BPFEventProbe
        POST_BUILD
        COMMAND ${LLVM_STRIP} -d -g -S ${EVENTS_PROBE_BPF_OUTPUT})
endif()

bpf_skeleton(EventProbe)
add_dependencies(EventProbe_skeleton BPFEventProbe)
