# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

set(BPFTOOL "/usr/bin/bpftool") # TODO: the one in toolchain is old, need to update
set(BTF_FILE "/sys/kernel/btf/vmlinux")
set(VMLINUX_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/vmlinux)

file(MAKE_DIRECTORY ${VMLINUX_INCLUDE_DIR})
execute_process(
    COMMAND ${BPFTOOL} btf dump file ${BTF_FILE} format c
    OUTPUT_FILE ${VMLINUX_INCLUDE_DIR}/vmlinux.h
    ERROR_VARIABLE BPFTOOL_VMLINUX_ERROR
    RESULT_VARIABLE BPFTOOL_VMLINUX_RESULT
)

if(NOT ${BPFTOOL_VMLINUX_RESULT} EQUAL 0)
    message(FATAL_ERROR "Failed to dump vmlinux.h with bpftool: ${BPFTOOL_VMLINUX_ERROR}")
endif()
