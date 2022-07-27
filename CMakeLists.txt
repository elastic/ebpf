# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

cmake_minimum_required(VERSION 3.20)

project(ebpf)

list(APPEND CMAKE_MODULE_PATH "${CMAKE_CURRENT_SOURCE_DIR}/cmake/modules")

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -O2 -Wall -fPIC")
set(TARGET_DIR_DEFAULT "${CMAKE_CURRENT_BINARY_DIR}/target")
set(TARGET_DIR "${TARGET_DIR_DEFAULT}" CACHE STRING "Custom target directory")
set(TARGET_TEST_DIR "${TARGET_DIR}/test")
set(TARGET_INCLUDE_DIR "${TARGET_DIR}/include")
set(TARGET_EBPF_DIR "${TARGET_DIR}/ebpf")

file(MAKE_DIRECTORY ${TARGET_DIR})
file(MAKE_DIRECTORY ${TARGET_INCLUDE_DIR})
file(MAKE_DIRECTORY ${TARGET_EBPF_DIR})
file(MAKE_DIRECTORY ${TARGET_TEST_DIR})

include(ExternalProject)
include(libelf)
include(libbpf)
include(arch)
include(BPF)
include(GoogleTest)

add_subdirectory(GPL)
add_subdirectory(non-GPL)
