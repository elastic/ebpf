# SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

# Copyright (C) 2021 Elasticsearch BV
#
# This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses, you
# may choose either one of them if you use this software.

set(KPROBECONNECTHOOK_CFLAGS
                        -g -O2
                        -target bpf
                        -D__TARGET_ARCH_${ARCH_TRUNC}
                        -D__${ARCH}__
                        -I${LIBBPF_TARGET_INCLUDE_DIR}
                        -I${LIBBPF_UAPI_INCLUDE_DIR}
                        -I${CMAKE_SOURCE_DIR}/non-GPL/Common
                        -fno-ident)

set(KPROBECONNECTHOOK_BPF_OUTPUT ${HOSTISOLATION_EBPF_OBJECT_DIR}/KprobeConnectHook.bpf.o)
add_custom_command(OUTPUT ${KPROBECONNECTHOOK_BPF_OUTPUT}
                  COMMAND ${EBPF_EXTERNAL_ENV_FLAGS} ${CLANG} ${KPROBECONNECTHOOK_CFLAGS} -c ${CMAKE_CURRENT_SOURCE_DIR}/KprobeConnectHook.bpf.c -o ${KPROBECONNECTHOOK_BPF_OUTPUT}
                  COMMENT "Building ${KPROBECONNECTHOOK_BPF_OUTPUT}"
                  DEPENDS libbpf
                  IMPLICIT_DEPENDS C ${CMAKE_CURRENT_SOURCE_DIR}/KprobeConnectHook.bpf.c)

add_custom_target(BPFKprobeConnectHook ALL DEPENDS ${HOSTISOLATION_EBPF_OBJECT_DIR}/KprobeConnectHook.bpf.o)

