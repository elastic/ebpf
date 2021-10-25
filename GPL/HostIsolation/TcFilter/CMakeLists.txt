# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

# BPF program
include(BPFDefinitions)

set(TCFILTER_CFLAGS 
                -g -O2 -nostdinc -isystem ${NOSTDINC_INCLUDES}
                -I${CMAKE_SOURCE_DIR}/contrib/kernel_hdrs
                -D__KERNEL__
                -D__BPF_TRACING
                -Wno-unused-value
                -Wno-pointer-sign
                -Wno-compare-distinct-pointer-types
                -Wno-gnu-variable-sized-type-not-at-end
                -Wno-address-of-packed-member
                -Wno-tautological-compare
                -fno-asynchronous-unwind-tables
                -fno-stack-protector)


add_custom_command(OUTPUT TcFilter.bpf.o
                  COMMAND ${CLANG} ${TCFILTER_CFLAGS} -emit-llvm -c ${CMAKE_CURRENT_SOURCE_DIR}/TcFilter.bpf.c -o - | ${LLC} -march=bpf -mcpu=v2 -filetype=obj -o TcFilter.bpf.o
                  COMMENT "Building TcFilter.bpf.o")

add_custom_target(BPFTcFilter ALL DEPENDS TcFilter.bpf.o)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/TcFilter.bpf.o DESTINATION ${TARGET_EBPF_DIR})

# BPF_PROG_TEST_RUN gtests
include(GoogleTest)

add_executable(BPFTcFilterTests BPFTcFilterTests.cpp ${GTEST_MAIN})
target_include_directories(BPFTcFilterTests PRIVATE 
    "${LIBBPF_UAPI_INCLUDE_DIR}"
    "${LIBBPF_INCLUDE_DIR}"
    "${GTEST_INCLUDE}")

add_dependencies(BPFTcFilterTests BPFTcFilter)

target_link_libraries(BPFTcFilterTests ${LIBBPF_LIB} ${LIBELF_LIB} ${GTEST_LIB} -pthread -lz)
add_dependencies(BPFTcFilterTests libbpf libelf gtest)

install(TARGETS BPFTcFilterTests RUNTIME DESTINATION ${TARGET_TEST_DIR})
