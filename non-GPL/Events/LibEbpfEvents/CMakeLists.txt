# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

add_library(LibEbpfEvents LibEbpfEvents.c)
add_dependencies(LibEbpfEvents EventProbe_skeleton libbpf BPFEventProbe)
target_include_directories(LibEbpfEvents PRIVATE
    "${TARGET_INCLUDE_DIR}"
    "${LIBBPF_TARGET_INCLUDE_DIR}"
    "${LIBBPF_UAPI_INCLUDE_DIR}")

configure_file(LibEbpfEvents.h ${TARGET_INCLUDE_DIR} COPYONLY)
