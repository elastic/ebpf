# SPDX-License-Identifier: GPL-2.0

#
# Elastic eBPF
# Copyright 2021 Elasticsearch BV
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#

# BPF program
include(BPFDefinitions)

set(TCFILTER_CFLAGS 
                -g -O2 -nostdinc -isystem ${NOSTDINC_INCLUDES}
                -I${PROJECT_SOURCE_DIR}/contrib/kernel_hdrs
                -D__KERNEL__
                -D__BPF_TRACING
                -Wno-unused-value
                -Wno-pointer-sign
                -Wno-compare-distinct-pointer-types
                -Wno-gnu-variable-sized-type-not-at-end
                -Wno-address-of-packed-member
                -Wno-tautological-compare
                -fno-asynchronous-unwind-tables
                -fno-stack-protector)


set(TCFILTER_BPF_OUTPUT ${TARGET_EBPF_DIR}/TcFilter.bpf.o)
add_custom_command(OUTPUT ${TCFILTER_BPF_OUTPUT}
                  COMMAND ${CLANG} ${TCFILTER_CFLAGS} -emit-llvm -c ${CMAKE_CURRENT_SOURCE_DIR}/TcFilter.bpf.c -o - | ${LLC} -march=bpf -mcpu=v2 -filetype=obj -o  ${TCFILTER_BPF_OUTPUT}
                  COMMENT "Building  ${TCFILTER_BPF_OUTPUT}"
                  DEPENDS ${CMAKE_CURRENT_SOURCE_DIR}/TcFilter.bpf.c)

add_custom_target(BPFTcFilter ALL DEPENDS  ${TCFILTER_BPF_OUTPUT})

# BPF_PROG_TEST_RUN gtests
include(GoogleTest)

add_executable(BPFTcFilterTests BPFTcFilterTests.cpp ${GTEST_MAIN})
set_target_properties(BPFTcFilterTests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${TARGET_TEST_DIR})
target_include_directories(BPFTcFilterTests PRIVATE 
    "${LIBBPF_TARGET_INCLUDE_DIR}"
    "${LIBBPF_UAPI_INCLUDE_DIR}"
    "${LIBBPF_INCLUDE_DIR}"
    "${GTEST_INCLUDE}")

add_dependencies(BPFTcFilterTests BPFTcFilter)

target_link_libraries(BPFTcFilterTests ${LIBBPF_LIB} ${LIBELF_LIB} ${GTEST_LIB} -pthread -lz)
add_dependencies(BPFTcFilterTests libbpf libelf gtest)

