# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

add_library(HostIsolation STATIC
    TcLoader.c
    KprobeLoader.c
    UpdateMaps.c
    Common.c)

target_include_directories(HostIsolation PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${LIBBPF_TARGET_INCLUDE_DIR}"
    "${LIBBPF_UAPI_INCLUDE_DIR}"
    "${LIBBPF_INCLUDE_DIR}")

add_dependencies(HostIsolation libbpf libelf)
target_link_libraries(
    HostIsolation ${LIBBPF_LIB} ${LIBELF_LIB} -lz)
add_dependencies(HostIsolation libbpf libelf)

configure_file(TcLoader.h ${TARGET_INCLUDE_DIR} COPYONLY)
configure_file(KprobeLoader.h ${TARGET_INCLUDE_DIR} COPYONLY)
configure_file(UpdateMaps.h ${TARGET_INCLUDE_DIR} COPYONLY)
configure_file(Common.h ${TARGET_INCLUDE_DIR} COPYONLY)
