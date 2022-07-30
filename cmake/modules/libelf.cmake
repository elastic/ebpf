# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

set(LIBELF_SRC "${PROJECT_SOURCE_DIR}/contrib/elftoolchain")
set(LIBELF_BUILD_DIR "${PROJECT_BINARY_DIR}/libelf-external-prefix/src/libelf-external-build")
set(LIBELF_LIB "${LIBELF_BUILD_DIR}/libelf.a")

ExternalProject_Add(
    libelf-external
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND CC=${CMAKE_C_COMPILER} ${EBPF_EXTERNAL_ENV_FLAGS} MFLAGS= MAKEFLAGS= WITH_TESTS=no WITH_BUILD_TOOLS=no WITH_ADDITIONAL_DOCUMENTATION=no WITH_PE=no WITH_ISA=no MAKEOBJDIR=${LIBELF_BUILD_DIR} bmake -j${NPROC} -C ${LIBELF_SRC} -e
    BUILD_IN_SOURCE 0
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${LIBELF_LIB}
)

add_library(libelf STATIC IMPORTED GLOBAL)
set_property(TARGET libelf PROPERTY IMPORTED_LOCATION "${LIBELF_LIB}")
add_dependencies(libelf libelf-external)
