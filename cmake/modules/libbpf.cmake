# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

set(LIBBPF_CONTRIB_DEFAULT "${PROJECT_SOURCE_DIR}/contrib/libbpf")
set(LIBBPF_CONTRIB "${LIBBPF_CONTRIB_DEFAULT}" CACHE STRING "Custom libbpf source directory")

set(LIBBPF_SRC "${LIBBPF_CONTRIB}/src")
set(LIBBPF_BUILD_DIR "${PROJECT_BINARY_DIR}/libbpf-external-prefix/src/libbpf-external-build")
set(LIBBPF_TARGET_INCLUDE_DIR "${PROJECT_BINARY_DIR}/libbpf-external-prefix/src/libbpf-external-target")
set(LIBBPF_LIB "${LIBBPF_BUILD_DIR}/libbpf.a")

# This is somewhat ugly and makes me sad but is unfortunately necessary.
#
# This repository needs to be buildable as a part of projects where the kernel
# headers aren't available or (ahem... looking at you endpoint) too old to be
# useable (e.g. linux/bpf.h is absent).
#
# Libbpf ships with a _subset_ of the newer kernel headers that are new enough
# to build this repository. We define a cache variable here pointing to that
# directory and do target_include_directories(... PRIVATE ${LIBBPF_UAPI_INCLUDE_DIR})
# on all targets that need Linux headers.
#
# We need to ensure that we make these headers a PRIVATE include. If we make it
# PUBLIC, it'll propagate to other targets that link against the libraries in
# this repository, and, if those targets also include older linux headers from
# their toolchains, we'll be including two different sets of Linux headers
# corresponding to different kernel versions. This can lead to build failures
# as the headers were never meant to be used like this.
set(LIBBPF_UAPI_INCLUDE_DIR "${LIBBPF_CONTRIB}/include/uapi"
    CACHE INTERNAL "Path to subset of UAPI headers that ship with libbpf")

ExternalProject_Add(
    libbpf-external
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND CC=${CMAKE_C_COMPILER} ${EBPF_EXTERNAL_ENV_FLAGS} make -j${NPROC} -C ${LIBBPF_SRC} BUILD_STATIC_ONLY=1 NO_PKG_CONFIG=1 OBJDIR=${LIBBPF_BUILD_DIR} INCLUDEDIR= LIBDIR= UAPIDIR= CFLAGS=${CMAKE_C_FLAGS} DESTDIR=${LIBBPF_TARGET_INCLUDE_DIR} install
    BUILD_IN_SOURCE 0
    INSTALL_COMMAND ""
    DEPENDS libelf libz
    BUILD_BYPRODUCTS ${LIBBPF_LIB} ${LIBBPF_TARGET_INCLUDE_DIR}
)

# https://gitlab.kitware.com/cmake/cmake/-/issues/15052
#
# INTERFACE_INCLUDE_DIRECTORIES cannot include a nonexistent directory but
# ${LIBBPF_TARGET_INCLUDE_DIR} is created at build time. Create it here as a
# workaround
file(MAKE_DIRECTORY "${LIBBPF_TARGET_INCLUDE_DIR}")

add_library(libbpf STATIC IMPORTED GLOBAL)
set_property(TARGET libbpf PROPERTY IMPORTED_LOCATION "${LIBBPF_LIB}")
set_property(TARGET libbpf PROPERTY INTERFACE_INCLUDE_DIRECTORIES "${LIBBPF_TARGET_INCLUDE_DIR}")
set_property(TARGET libbpf PROPERTY INTERFACE_LINK_LIBRARIES "libelf;libz")
add_dependencies(libbpf libbpf-external)
