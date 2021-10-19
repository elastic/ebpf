# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

set(LIBBPF_SRC "${PROJECT_SOURCE_DIR}/contrib/libbpf/src")
set(LIBBPF_BUILD_DIR "${PROJECT_BINARY_DIR}/libbpf-prefix/src/libbpf-build")
set(LIBBPF_TARGET_DIR "${PROJECT_BINARY_DIR}/libbpf-prefix/src/libbpf-target")
set(LIBBPF_LIB "${LIBBPF_BUILD_DIR}/libbpf.a")
message(STATUS "[contrib] libbpf in '${LIBBPF_SRC}'")

ExternalProject_Add(
    libbpf
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND make -C ${LIBBPF_SRC} BUILD_STATIC_ONLY=1 NO_PKG_CONFIG=1 OBJDIR=${LIBBPF_BUILD_DIR} INCLUDEDIR= LIBDIR= UAPIDIR= CFLAGS=${CMAKE_C_FLAGS} DESTDIR=${LIBBPF_TARGET_DIR} install
    BUILD_IN_SOURCE 0
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${LIBBPF_LIB}
)
