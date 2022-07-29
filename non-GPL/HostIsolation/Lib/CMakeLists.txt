# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

add_library(EbpfHostIsolation STATIC
    TcLoader.c
    KprobeLoader.c
    UpdateMaps.c
    Common.c)

target_include_directories(EbpfHostIsolation
    PRIVATE
    "${LIBBPF_UAPI_INCLUDE_DIR}"
    PUBLIC
    "${CMAKE_CURRENT_SOURCE_DIR}")

target_link_libraries(EbpfHostIsolation libbpf)
