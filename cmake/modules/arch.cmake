# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

if (NOT ARCH)
    log(FATAL_ERROR "An architecture must be specified, either \"aarch64\" or \"x86_64\" via -DARCH=<arch>")
endif()

if (ARCH STREQUAL "x86_64")
    set(ARCH_TRUNC "x86")
elseif(ARCH STREQUAL "aarch64")
    set(ARCH_TRUNC "arm64")
else()
    log(FATAL_ERROR "Invalid architecture ${ARCH}")
endif()
