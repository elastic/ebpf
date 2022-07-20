# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

if (NOT ARCH)
    set(ARCH "${CMAKE_HOST_SYSTEM_PROCESSOR}")
endif()
if (NOT ARCH_TRUNC)
    string(REPLACE "x86_64" "x86" ARCH_TRUNC ${ARCH})
endif()
