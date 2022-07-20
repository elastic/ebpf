# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

add_library(EbpfEvents EbpfEvents.c)
add_dependencies(EbpfEvents EventProbe_skeleton libbpf BPFEventProbe)
target_include_directories(EbpfEvents PRIVATE
    "${TARGET_INCLUDE_DIR}"
    "${LIBBPF_TARGET_INCLUDE_DIR}"
    "${LIBBPF_UAPI_INCLUDE_DIR}")

configure_file(EbpfEvents.h ${TARGET_INCLUDE_DIR} COPYONLY)
add_subdirectory(TestLoader)
