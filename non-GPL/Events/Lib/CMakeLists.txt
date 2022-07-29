# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

add_library(EbpfEvents STATIC EbpfEvents.c)
add_dependencies(EbpfEvents EventProbe_skeleton libbpf BPFEventProbe)
target_link_libraries(EbpfEvents libbpf)

target_include_directories(EbpfEvents
    PRIVATE
    "${LIBBPF_UAPI_INCLUDE_DIR}"
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}"
    "${PROJECT_BINARY_DIR}/GPL/Events"  # For the skeleton header
    "${PROJECT_SOURCE_DIR}/GPL/Events") # For EbpfEventProto.h
