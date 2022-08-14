# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.


set(LIBBPF_CONTRIB "${PROJECT_SOURCE_DIR}/contrib/libbpf")
set(LIBBPF_SRC "${LIBBPF_CONTRIB}/src")

set(LIBBPF_BUILD_DIR "${PROJECT_BINARY_DIR}/contrib/libbpf")

set(LIBBPF_LIB "${EBPF_INSTALL_DIR}/lib/libbpf.a")
set(LIBBPF_UAPI_INCLUDE_DIR "${EBPF_INSTALL_DIR}/include/bpf/uapi")

ExternalProject_Add(
    libbpf-external
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BINARY_DIR ${LIBBPF_BUILD_DIR}
    BUILD_COMMAND CC=${CMAKE_C_COMPILER} ${EBPF_EXTERNAL_ENV_FLAGS} make -j${NPROC} -C ${LIBBPF_SRC} BUILD_STATIC_ONLY=1 LIBDIR=/lib INCLUDEDIR=/include UAPIDIR=/include/bpf/uapi OBJDIR=${LIBBPF_BUILD_DIR} CFLAGS=${CMAKE_C_FLAGS} DESTDIR=${EBPF_INSTALL_DIR}
    BUILD_IN_SOURCE 0
    INSTALL_COMMAND ${EBPF_EXTERNAL_ENV_FLAGS} make -j${NPROC} -C ${LIBBPF_SRC} BUILD_STATIC_ONLY=1 INCLUDEDIR=/include LIBDIR=/lib UAPIDIR=/include/bpf/uapi OBJDIR=${LIBBPF_BUILD_DIR} DESTDIR=${EBPF_INSTALL_DIR} install install_uapi_headers
    DEPENDS libelf libz
    BUILD_BYPRODUCTS ${LIBBPF_LIB}
)

file(MAKE_DIRECTORY "${LIBBPF_UAPI_INCLUDE_DIR}")

add_library(libbpf STATIC IMPORTED GLOBAL)
set_property(TARGET libbpf PROPERTY IMPORTED_LOCATION ${LIBBPF_LIB})
set_property(TARGET libbpf PROPERTY INTERFACE_INCLUDE_DIRECTORIES ${EBPF_INSTALL_DIR}/include ${LIBBPF_UAPI_INCLUDE_DIR})
set_property(TARGET libbpf PROPERTY INTERFACE_LINK_LIBRARIES libelf libz)
add_dependencies(libbpf libbpf-external)
