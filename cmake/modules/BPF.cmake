# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.


# Tools and defines
option(USE_BUILTIN_VMLINUX "If true, use the builtin vmlinux.h for building eBPF probes instead of generating one from system BTF" True)
option(USE_ZIG_BPF_COMPILER "If true, use zig's drop in replacement to clang/llvm compiler" True)

if (USE_ZIG_BPF_COMPILER)
    set(BPF_COMPILER_ENV "ZIG_GLOBAL_CACHE_DIR=${PROJECT_BINARY_DIR}/zigcache")
    set(BPF_COMPILER zig)
    set(BPF_COMPILER_FLAGS
        cc
        --target=bpfel-freestanding-none
    )
else()
    set(BPF_COMPILER_ENV "")
    set(BPF_COMPILER clang)
    set(BPF_COMPILER_FLAGS
        -target=bpf
    )
endif()

set(LLVM_STRIP llvm-strip)
set(BPFTOOL bpftool)
set(BTF_FILE "/sys/kernel/btf/vmlinux")

# Standard includes
if(NOT USE_ZIG_BPF_COMPILER)
    execute_process(COMMAND ${CLANG} -print-file-name=include
                    OUTPUT_VARIABLE NOSTDINC_INCLUDES ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
endif()

if(NOT USE_BUILTIN_VMLINUX)
    set(VMLINUX_INSTALL_COMMAND /bin/sh -c "${BPFTOOL} btf dump file ${BTF_FILE} format c > ${EBPF_INSTALL_DIR}/include/vmlinux.h")
else()
    set(VMLINUX_INSTALL_COMMAND /bin/sh -c "cp ${PROJECT_SOURCE_DIR}/contrib/vmlinux/${ARCH}/vmlinux.h ${EBPF_INSTALL_DIR}/include/vmlinux.h")
endif()

ExternalProject_Add(
    vmlinux-external
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    BUILD_IN_SOURCE 0
    INSTALL_COMMAND ${VMLINUX_INSTALL_COMMAND}
    BUILD_BYPRODUCTS ${EBPF_INSTALL_DIR}/include/vmlinux.h
)

add_library(vmlinux INTERFACE)
set_property(TARGET vmlinux PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${EBPF_INSTALL_DIR}/include)
add_dependencies(vmlinux vmlinux-external)


function (ebpf_probe_target target)
    set(options OPTIONAL GENSKELETON INSTALL)
    set(multiValueArgs FLAGS SOURCES DEPENDENCIES PUBLIC_HEADERS DEPENDS)

    cmake_parse_arguments(EBPF_PROBE "${options}" ""
        "${multiValueArgs}" ${ARGN})

    file(MAKE_DIRECTORY ${CMAKE_CURRENT_BINARY_DIR}/public-headers)
    set(OUT_FILE ${CMAKE_CURRENT_BINARY_DIR}/${target}.bpf.o)

    if (EBPF_PROBE_GENSKELETON)
        set(SKEL_FILE ${CMAKE_CURRENT_BINARY_DIR}/public-headers/${target}.skel.h)
        set(SKELETON_CMD ${BPFTOOL} gen skeleton ${OUT_FILE} > ${SKEL_FILE})
    else()
        set(SKELETON_CMD /bin/sh -c "exit 0")
    endif()

    if (NOT CMAKE_BUILD_TYPE STREQUAL Debug)
        set(STRIP_CMD ${LLVM_STRIP} -d -g -S ${OUT_FILE})
    else()
        set(STRIP_CMD /bin/sh -c "exit 0")
    endif()

    set(EBPF_PROBE_DEPFILE ${CMAKE_CURRENT_BINARY_DIR}/${target}.bpf.d)

    add_custom_command(
        OUTPUT ${OUT_FILE} ${SKEL_FILE}
        COMMAND ${EBPF_EXTERNAL_ENV_FLAGS} ${BPF_COMPILER_ENV} ${BPF_COMPILER} ${BPF_COMPILER_FLAGS} -MD -MF ${EBPF_PROBE_DEPFILE} ${EBPF_PROBE_FLAGS} -c ${EBPF_PROBE_SOURCES} -o ${OUT_FILE}
        COMMAND ${STRIP_CMD}
        COMMAND ${SKELETON_CMD}
        DEPENDS ${EBPF_PROBE_DEPENDS}
    )

    add_custom_target(${target}_Probe DEPENDS ${OUT_FILE} ${SKEL_FILE})

    add_dependencies(${target}_Probe ${EBPF_PROBE_DEPENDENCIES} libbpf vmlinux)

    add_library(${target} INTERFACE)
    add_dependencies(${target} ${target}_Probe)

    foreach(HDR ${EBPF_PROBE_PUBLIC_HEADERS})
        configure_file(${HDR} ${CMAKE_CURRENT_BINARY_DIR}/public-headers/${HDR} COPYONLY)
    endforeach()

    if (EBPF_PROBE_GENSKELETON)
        set(EBPF_PROBE_PUBLIC_HEADERS ${EBPF_PROBE_PUBLIC_HEADERS} ${SKEL_FILE})
    endif()

    set_property(TARGET ${target} PROPERTY PUBLIC_HEADER
        ${EBPF_PROBE_PUBLIC_HEADERS}
    )

    set_property(TARGET ${target} PROPERTY RESOURCE
        ${OUT_FILE}
    )

    target_include_directories(${target} INTERFACE ${CMAKE_CURRENT_BINARY_DIR}/public-headers)

    if (EBPF_PROBE_INSTALL)
        install(TARGETS
            ${target}
            RESOURCE DESTINATION ${EBPF_INSTALL_DIR}/probes
            PUBLIC_HEADER DESTINATION ${EBPF_INSTALL_DIR}/include
        )
    endif()

endfunction()
