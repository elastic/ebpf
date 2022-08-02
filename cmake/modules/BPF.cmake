# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.


# Tools and defines
option(USE_BUILTIN_VMLINUX "If true, use the builtin vmlinux.h for building eBPF probes instead of generating one from system BTF" True)
option(USE_ZIG_BPF_COMPILER "If true, use zig's drop in replacement to clang/llvm compiler" True)

if (USE_ZIG_BPF_COMPILER)
    set(BPF_COMPILER zig)
    set(BPF_COMPILER_FLAGS
        cc
        --target=bpfel-freestanding-none
    )
else()
    set(BPF_COMPILER clang)
    set(BPF_COMPILER_FLAGS
        -target=bpf
    )
endif()

set(LLVM_STRIP llvm-strip)
set(BPFTOOL bpftool)
set(BTF_FILE "/sys/kernel/btf/vmlinux")

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
    set(VMLINUX_INCLUDE_DIR ${PROJECT_SOURCE_DIR}/contrib/vmlinux/${ARCH})
endif()

# Skeleton generation
macro(bpf_skeleton name)
    set(_object_file_path ${CMAKE_CURRENT_BINARY_DIR}/${name}.bpf.o)
    set(_skeleton_file_path ${CMAKE_CURRENT_BINARY_DIR}/${name}.skel.h)
    add_custom_target(
        ${name}_skeleton
        COMMAND ${BPFTOOL} gen skeleton ${_object_file_path} > ${_skeleton_file_path}
    )
endmacro()
