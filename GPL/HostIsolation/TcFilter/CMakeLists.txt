# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

# Copyright (C) 2021 Elasticsearch BV
#
# This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses, you
# may choose either one of them if you use this software.

set(TCFILTER_CFLAGS
                -g -O2 -nostdinc
                -I${PROJECT_SOURCE_DIR}/contrib/kernel_hdrs
                -I${LIBBPF_UAPI_INCLUDE_DIR}
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


set(TCFILTER_BPF_OUTPUT ${HOSTISOLATION_EBPF_OBJECT_DIR}/TcFilter.bpf.o)
add_custom_command(OUTPUT ${TCFILTER_BPF_OUTPUT}
                  COMMAND ${EBPF_EXTERNAL_ENV_FLAGS} ${BPF_COMPILER} ${BPF_COMPILER_FLAGS} ${TCFILTER_CFLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/TcFilter.bpf.c -o ${TCFILTER_BPF_OUTPUT}
                  COMMENT "Building  ${TCFILTER_BPF_OUTPUT}"
                  IMPLICIT_DEPENDS C ${CMAKE_CURRENT_SOURCE_DIR}/TcFilter.bpf.c)

add_custom_target(BPFTcFilter ALL DEPENDS  ${TCFILTER_BPF_OUTPUT})

# BPF_PROG_TEST_RUN gtests
add_executable(BPFTcFilterTests BPFTcFilterTests.cpp ${GTEST_MAIN})
target_include_directories(BPFTcFilterTests
    PRIVATE
    "${LIBBPF_UAPI_INCLUDE_DIR}"
    "${GTEST_INCLUDE}")

add_dependencies(BPFTcFilterTests BPFTcFilter)

# TODO: Remove "-lz" once we've vendored in libz
target_link_libraries(BPFTcFilterTests libbpf ${GTEST_LIB} -pthread -lz)
add_dependencies(BPFTcFilterTests libbpf libelf gtest)

