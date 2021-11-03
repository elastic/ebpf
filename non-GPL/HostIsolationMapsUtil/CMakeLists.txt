# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

# Library
add_library(UpdateMaps STATIC UpdateMaps.c)
target_include_directories(UpdateMaps PRIVATE 
    "${LIBBPF_TARGET_INCLUDE_DIR}"
    "${LIBBPF_UAPI_INCLUDE_DIR}"
    "${LIBBPF_INCLUDE_DIR}"
    "${PROJECT_SOURCE_DIR}/non-GPL/Common")

target_link_libraries(UpdateMaps Common ${LIBBPF_LIB} ${LIBELF_LIB} -lz)
add_dependencies(UpdateMaps Common libbpf libelf)

configure_file(UpdateMaps.h ${TARGET_INCLUDE_DIR} COPYONLY)

# UpdateIPsDemo using the library
add_executable(UpdateIPsDemo UpdateIPsDemo.c)
target_include_directories(UpdateIPsDemo PRIVATE 
    "${LIBBPF_TARGET_INCLUDE_DIR}"
    "${LIBBPF_UAPI_INCLUDE_DIR}"
    "${LIBBPF_INCLUDE_DIR}" 
    "${PROJECT_SOURCE_DIR}/non-GPL/Common")

target_link_libraries(UpdateIPsDemo UpdateMaps)

# UpdatePidsDemo using the library
add_executable(UpdatePidsDemo UpdatePidsDemo.c)
target_include_directories(UpdatePidsDemo PRIVATE 
    "${LIBBPF_TARGET_INCLUDE_DIR}"
    "${LIBBPF_UAPI_INCLUDE_DIR}"
    "${LIBBPF_INCLUDE_DIR}" 
    "${PROJECT_SOURCE_DIR}/non-GPL/Common")

target_link_libraries(UpdatePidsDemo UpdateMaps)
