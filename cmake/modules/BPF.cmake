
# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.


# Tools and defines
set(CLANG "clang")
set(LLC "llc")
set(BPFTOOL "bpftool")
set(BTF_FILE "/sys/kernel/btf/vmlinux")
option(USE_BUILTIN_VMLINUX "Whether or not to use the builtin vmlinux.h for building the BPF programs instead of trying to generate one from the system" False)

# Standard includes
execute_process(COMMAND ${CLANG} -print-file-name=include
                OUTPUT_VARIABLE NOSTDINC_INCLUDES ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)

if(NOT USE_BUILTIN_VMLINUX)
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
else()
    set(VMLINUX_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/contrib/vmlinux)
endif()

# Skeleton generation
macro(bpf_skeleton name)
    set(_object_file_path ${TARGET_EBPF_DIR}/${name}.bpf.o)
    set(_skeleton_file_path ${TARGET_INCLUDE_DIR}/${name}.skel.h)
    add_custom_target(
        ${name}_skeleton
        COMMAND ${BPFTOOL} gen skeleton ${_object_file_path} > ${_skeleton_file_path}
    )
endmacro()
