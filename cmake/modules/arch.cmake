# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

if (NOT ARCH)
    message(FATAL_ERROR "An architecture must be specified, either \"aarch64\" or \"x86_64\" via -DARCH=<arch>")
endif()

set(SUPPORTED_ARCHS x64 x86_64 aarch64 arm64)

if (${ARCH} IN_LIST SUPPORTED_ARCHS)
    if (ARCH STREQUAL "x86_64")
        set(ARCH_TRUNC "x64")
    elseif (ARCH STREQUAL "aarch64")
        set(ARCH_TRUNC "arm64")
    else ()
        set(ARCH_TRUNC ${ARCH})
    endif()
else()
    message(FATAL_ERROR "Unsupported architecture ${ARCH}, supported => ${SUPPORTED_ARCHS}")
endif()

include(ProcessorCount)
ProcessorCount(N)
set(NPROC ${N} CACHE INTERNAL "Number of Processors")

execute_process(
    COMMAND id -u
    OUTPUT_VARIABLE CURRENT_USER
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY
)

execute_process(
    COMMAND id -g
    OUTPUT_VARIABLE CURRENT_GROUP
    OUTPUT_STRIP_TRAILING_WHITESPACE
    COMMAND_ERROR_IS_FATAL ANY
)
