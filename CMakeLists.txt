# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

cmake_minimum_required(VERSION 3.20)

project(ebpf)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O2 -Wall -fPIC")


include(ExternalProject)
include(setup)
include(arch)
include(libz)
include(libelf)
include(libbpf)
include(BPF)
include(GoogleTest)

add_subdirectory(GPL)
add_subdirectory(non-GPL)
