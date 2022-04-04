# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

# Copyright (C) 2021 Elasticsearch BV
#
# This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses, you
# may choose either one of them if you use this software.

# BPF program

if (CMAKE_BUILD_TYPE STREQUAL Debug)
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
                -I${TARGET_INCLUDE_DIR}
                -I${LIBBPF_UAPI_INCLUDE_DIR}
                -I${LIBBPF_INCLUDE_DIR}
                -I${VMLINUX_INCLUDE_DIR}
                -I${EVENTS_PROBE_SOURCE_DIR}
                -fno-ident)

configure_file(EbpfEventProto.h ${TARGET_INCLUDE_DIR} COPYONLY)
set(EVENTS_PROBE_SOURCES ${EVENTS_PROBE_SOURCE_DIR}/EventProbe.bpf.c)
file(GLOB EVENTS_PROBE_INCLUDES "${EVENTS_PROBE_SOURCE_DIR}/*.h")
message(STATUS "Including: ${EVENTS_PROBE_INCLUDES}")

set(EVENTS_PROBE_BPF_OUTPUT ${TARGET_EBPF_DIR}/EventProbe.bpf.o)
add_custom_command(OUTPUT ${EVENTS_PROBE_BPF_OUTPUT}
                  COMMAND ${EBPF_EXTERNAL_ENV_FLAGS} ${CLANG} ${EVENTS_PROBE_CFLAGS} -c ${EVENTS_PROBE_SOURCES} -o ${EVENTS_PROBE_BPF_OUTPUT}
                  DEPENDS libbpf
                  DEPFILE ${EVENTS_PROBE_DEPFILE}
                  COMMENT "[bpf] building ${EVENTS_PROBE_BPF_OUTPUT}")

add_custom_target(BPFEventProbe ALL DEPENDS ${EVENTS_PROBE_BPF_OUTPUT})

if (NOT CMAKE_BUILD_TYPE STREQUAL Debug)
    add_custom_command(TARGET BPFEventProbe
        POST_BUILD
        COMMAND ${LLVM_STRIP} -d -g -S ${EVENTS_PROBE_BPF_OUTPUT}
        COMMENT "[bpf] stripping ${EVENTS_PROBE_BPF_OUTPUT}")
endif()


# BPF_PROG_TEST_RUN gtests
add_executable(BPFEventsTests BPFEventsTests.cpp ${GTEST_MAIN})
set_target_properties(BPFEventsTests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${TARGET_TEST_DIR})
target_include_directories(BPFEventsTests PRIVATE
    "${LIBBPF_TARGET_INCLUDE_DIR}"
    "${LIBBPF_UAPI_INCLUDE_DIR}"
    "${LIBBPF_INCLUDE_DIR}"
    "${TARGET_INCLUDE_DIR}"
    "${GTEST_INCLUDE}")

add_dependencies(BPFEventsTests BPFEventProbe)

bpf_skeleton(EventProbe)
add_dependencies(EventProbe_skeleton BPFEventProbe)

target_link_libraries(BPFEventsTests ${LIBBPF_LIB} ${LIBELF_LIB} ${GTEST_LIB} -pthread -lz)
add_dependencies(BPFEventsTests EventProbe_skeleton libbpf libelf gtest)
