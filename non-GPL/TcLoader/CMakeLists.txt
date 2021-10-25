# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

# Library
add_library(TcLoader STATIC TcLoader.c)
target_include_directories(TcLoader PRIVATE 
    "${LIBBPF_INCLUDE_DIR}"
    "${PROJECT_SOURCE_DIR}/non-GPL/Common")

add_dependencies(TcLoader libbpf libelf)
target_link_libraries(TcLoader Common ${LIBBPF_LIB} ${LIBELF_LIB} -lz)
add_dependencies(TcLoader Common libbpf libelf)

install(FILES TcLoader.h DESTINATION ${TARGET_INCLUDE_DIR})

# Demo using the library
add_executable(TcLoaderDemo TcLoaderDemo.c)
target_include_directories(TcLoaderDemo PRIVATE 
    "${LIBBPF_INCLUDE_DIR}"
    "${PROJECT_SOURCE_DIR}/non-GPL/Common")

target_link_libraries(TcLoaderDemo TcLoader)
