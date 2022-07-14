# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

add_executable(LibEbpfEventsTestLoader LibEbpfEventsTestLoader.c)
add_dependencies(LibEbpfEventsTestLoader LibEbpfEvents EventProbe_skeleton libbpf libelf)
target_link_libraries(LibEbpfEventsTestLoader LibEbpfEvents ${LIBBPF_LIB} ${LIBELF_LIB} -lz)

target_include_directories(LibEbpfEventsTestLoader PRIVATE
    "${LIBBPF_TARGET_INCLUDE_DIR}"
    "${LIBBPF_UAPI_INCLUDE_DIR}"
    "${LIBBPF_INCLUDE_DIR}"
    "${CMAKE_SOURCE_DIR}/GPL/Events"
    "${TARGET_INCLUDE_DIR}"
)
