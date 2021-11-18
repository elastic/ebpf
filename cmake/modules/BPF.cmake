
# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.


# Tools and defines
set(CLANG "clang")
set(LLC "llc")
set(BPFTOOL "/usr/bin/bpftool") # TODO: the one in toolchain is old, need to update
set(BTF_FILE "/sys/kernel/btf/vmlinux")

# Standard includes
execute_process(COMMAND ${CLANG} -print-file-name=include
                OUTPUT_VARIABLE NOSTDINC_INCLUDES ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)


set(VMLINUX_INCLUDE_DIR ${CMAKE_CURRENT_BINARY_DIR}/vmlinux)

# Vmlinux generation
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

# Skeleton generation fn
function (generate_skeleton _object_file_path _skeleton_file_path)
    execute_process(
        COMMAND ${BPFTOOL} gen skeleton ${_object_file_path}
        OUTPUT_FILE ${_skeleton_file_path}
        ERROR_VARIABLE BPFTOOL_GEN_SKELETON_ERROR
        RESULT_VARIABLE BPFTOOL_GEN_SKELETON_RESULT
    )
    if (NOT ${BPFTOOL_GEN_SKELETON_RESULT} EQUAL 0)
        message(FATAL_ERROR "Failed to generate skeleton with bpftool: ${BPFTOOL_GEN_SKELETON_ERROR}")
    endif()
endfunction()
