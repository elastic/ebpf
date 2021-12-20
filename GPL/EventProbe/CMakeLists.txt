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

set(EVENTS_PROBE_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(EVENTS_PROBE_DEPFILE ${CMAKE_CURRENT_BINARY_DIR}/EventProbe.bpf.d)
set(EVENTS_PROBE_CFLAGS
                -g -O2
                -target bpf
                -MD -MF ${EVENTS_PROBE_DEPFILE}
                -D__KERNEL__
                -D__TARGET_ARCH_${ARCH_TRUNC}
                -D__${ARCH}__
                -I${LIBBPF_TARGET_INCLUDE_DIR}
                -I${TARGET_INCLUDE_DIR}
                -I${LIBBPF_UAPI_INCLUDE_DIR}
                -I${LIBBPF_INCLUDE_DIR}
                -I${VMLINUX_INCLUDE_DIR}
                -I${EVENTS_PROBE_SOURCE_DIR}
                -I${PROJECT_SOURCE_DIR}/include)

configure_file(EbpfEventProto.h ${TARGET_INCLUDE_DIR} COPYONLY)
set(EVENTS_PROBE_SOURCES ${EVENTS_PROBE_SOURCE_DIR}/EventProbe.bpf.c)
file(GLOB EVENTS_PROBE_INCLUDES "${EVENTS_PROBE_SOURCE_DIR}/*.h")
message(STATUS "Including: ${EVENTS_PROBE_INCLUDES}")

set(EVENTS_PROBE_BPF_OUTPUT ${TARGET_EBPF_DIR}/EventProbe.bpf.o)
add_custom_command(OUTPUT ${EVENTS_PROBE_BPF_OUTPUT}
                  COMMAND ${EBPF_EXTERNAL_ENV_FLAGS} ${CLANG} ${EVENTS_PROBE_CFLAGS} -c ${EVENTS_PROBE_SOURCES} -o ${EVENTS_PROBE_BPF_OUTPUT}
                  DEPENDS libbpf
                  DEPFILE ${EVENTS_PROBE_DEPFILE}
                  COMMENT "[bpf] building ${EVENTS_PROBE_BPF_OUTPUT}")

add_custom_target(BPFEventProbe ALL DEPENDS ${TARGET_EBPF_DIR}/EventProbe.bpf.o)

# BPF_PROG_TEST_RUN gtests
add_executable(BPFEventsTests BPFEventsTests.cpp ${GTEST_MAIN})
set_target_properties(BPFEventsTests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${TARGET_TEST_DIR})
target_include_directories(BPFEventsTests PRIVATE
    "${LIBBPF_TARGET_INCLUDE_DIR}"
    "${LIBBPF_UAPI_INCLUDE_DIR}"
    "${LIBBPF_INCLUDE_DIR}"
    "${TARGET_INCLUDE_DIR}"
    "${GTEST_INCLUDE}")

add_dependencies(BPFEventsTests BPFEventProbe)

bpf_skeleton(EventProbe)
add_dependencies(EventProbe_skeleton BPFEventProbe)

target_link_libraries(BPFEventsTests ${LIBBPF_LIB} ${LIBELF_LIB} ${GTEST_LIB} -pthread -lz)
add_dependencies(BPFEventsTests EventProbe_skeleton libbpf libelf gtest)
