# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.


set(LIBELF_SRC "${PROJECT_SOURCE_DIR}/contrib/elftoolchain/libelf")
set(LIBELF_BUILD_DIR "${PROJECT_BINARY_DIR}/contrib/elftoolchain")
set(LIBELF_LIB "${EBPF_INSTALL_DIR}/lib/libelf_pic.a")

ExternalProject_Add(
    libelf-external
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BINARY_DIR ${LIBELF_BUILD_DIR}
    BUILD_COMMAND make -C ${LIBELF_SRC} V=1 MAKEOBJDIR=${LIBELF_BUILD_DIR}
    INSTALL_COMMAND cp ${LIBELF_BUILD_DIR}/libelf/libelf_pic.a ${EBPF_INSTALL_DIR}/lib/libelf_pic.a
    BUILD_IN_SOURCE 0
    BUILD_BYPRODUCTS ${LIBELF_LIB}
)

add_library(libelf STATIC IMPORTED GLOBAL)
set_property(TARGET libelf PROPERTY IMPORTED_LOCATION "${LIBELF_LIB}")
set_property(TARGET libelf PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${EBPF_INSTALL_DIR}/include")
add_dependencies(libelf libelf-external)
