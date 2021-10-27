# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

cmake_minimum_required(VERSION 3.10)

project(ebpf)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O2 -Wall -fPIC")
set(TARGET_DIR_DEFAULT "${CMAKE_CURRENT_BINARY_DIR}/target")
set(TARGET_DIR "${TARGET_DIR_DEFAULT}" CACHE STRING "Custom target directory")
set(TARGET_TMP_DIR "${CMAKE_CURRENT_BINARY_DIR}/target-tmp")
set(TARGET_TEST_DIR "${TARGET_DIR}/test")
set(TARGET_INCLUDE_DIR "${TARGET_DIR}/include")
set(TARGET_EBPF_DIR "${TARGET_DIR}/ebpf")
set(LIBEBPF_LIB "${TARGET_DIR}/libeBPF.a")

# target
file(MAKE_DIRECTORY ${TARGET_DIR})
file(MAKE_DIRECTORY ${TARGET_TMP_DIR})
file(MAKE_DIRECTORY ${TARGET_INCLUDE_DIR})
file(MAKE_DIRECTORY ${TARGET_EBPF_DIR})
file(MAKE_DIRECTORY ${TARGET_TEST_DIR})

include(ExternalProject)
include(libelf)
include(libbpf)

add_subdirectory(GPL/HostIsolation/KprobeConnectHook)
add_subdirectory(GPL/HostIsolation/TcFilter)

add_subdirectory(non-GPL/Common)
add_subdirectory(non-GPL/HostIsolation/KprobeConnectHook)
add_subdirectory(non-GPL/HostIsolationMapsUtil)
add_subdirectory(non-GPL/TcLoader)

# libeBPF
add_custom_command(OUTPUT ${LIBEBPF_LIB}
                  WORKING_DIRECTORY ${TARGET_TMP_DIR}
                  COMMAND ar x ${LIBBPF_LIB}
                  COMMAND ar x ${LIBELF_LIB}
                  COMMAND ar x $<TARGET_FILE:UpdateMaps>
                  COMMAND ar x $<TARGET_FILE:KprobeLoader>
                  COMMAND ar x $<TARGET_FILE:TcLoader>
                  COMMAND ar x $<TARGET_FILE:Common>
                  COMMAND ar cr ${LIBEBPF_LIB} *.o
                  COMMENT "Assembling ${LIBEBPF_LIB}"
                  DEPENDS libbpf libelf UpdateMaps KprobeLoader TcLoader Common)

add_library(EbpfLib STATIC IMPORTED GLOBAL)
set_property(TARGET EbpfLib PROPERTY
    IMPORTED_LOCATION "${LIBEBPF_LIB}")
add_dependencies(EbpfLib TcLoader KprobeLoader UpdateMaps)

add_library(Ebpf ALIAS EbpfLib)
