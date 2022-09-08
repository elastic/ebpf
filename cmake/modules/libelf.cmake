# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.


set(LIBELF_SRC "${PROJECT_SOURCE_DIR}/contrib/elftoolchain")
set(LIBELF_BUILD_DIR "${PROJECT_BINARY_DIR}/contrib/libelf")
set(LIBELF_LIB "${EBPF_INSTALL_DIR}/lib/libelf.a")

ExternalProject_Add(
    libelf-external
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BINARY_DIR ${LIBELF_BUILD_DIR}
    BUILD_COMMAND CC=${CMAKE_C_COMPILER} ${EBPF_EXT_ENV_FLAGS} BINOWN=${CURRENT_USER} BINGRP=${CURRENT_GROUP} MFLAGS= MAKEFLAGS= WITH_TESTS=no WITH_BUILD_TOOLS=no BUILD_STATIC_ONLY=1 WITH_ADDITIONAL_DOCUMENTATION=no WITH_PE=no WITH_ISA=no MAKEOBJDIR=${LIBELF_BUILD_DIR} INCSDIR=/include /bin/sh -c "bmake -j${NPROC} -C ${LIBELF_SRC} -e"
    BUILD_IN_SOURCE 0
    INSTALL_COMMAND CC=${CMAKE_C_COMPILER} ${EBPF_EXT_ENV_FLAGS} BINOWN=${CURRENT_USER} BINGRP=${CURRENT_GROUP} MFLAGS= MAKEFLAGS= WITH_TESTS=no WITH_BUILD_TOOLS=no BUILD_STATIC_ONLY=1 WITH_ADDITIONAL_DOCUMENTATION=no WITH_PE=no WITH_ISA=no MAKEOBJDIR=${LIBELF_BUILD_DIR} /bin/sh -c "bmake -j${NPROC} -C ${LIBELF_SRC} -e install DESTDIR=${EBPF_INSTALL_DIR} prefix='' INCSDIR=/include"
    BUILD_BYPRODUCTS ${LIBELF_LIB}
)

add_library(libelf STATIC IMPORTED GLOBAL)
set_property(TARGET libelf PROPERTY IMPORTED_LOCATION "${LIBELF_LIB}")
set_property(TARGET libelf PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${EBPF_INSTALL_DIR}/include")
add_dependencies(libelf libelf-external)
