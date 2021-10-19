# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

# BPF program
include(BPFDefinitions)
include(arch)

add_custom_command(OUTPUT KprobeConnectHook.bpf.o
                  COMMAND ${CLANG} -g -O2 -target bpf -D__TARGET_ARCH_${ARCH_TRUNC} -D__${ARCH}__ -I${LIBBPF_TARGET_DIR} -I${CMAKE_SOURCE_DIR}/non-GPL/Common/ -I${CMAKE_SOURCE_DIR}/contrib/libbpf/include -I${CMAKE_SOURCE_DIR}/contrib/libbpf/include/uapi -c ${CMAKE_CURRENT_SOURCE_DIR}/KprobeConnectHook.bpf.c -o KprobeConnectHook.bpf.o
                  COMMENT "Building KprobeConnectHook.bpf.o"
                  DEPENDS libbpf)

add_custom_target(BPFKprobeConnectHook ALL DEPENDS KprobeConnectHook.bpf.o)

install(FILES ${CMAKE_CURRENT_BINARY_DIR}/KprobeConnectHook.bpf.o DESTINATION ${TARGET_EBPF_DIR})
