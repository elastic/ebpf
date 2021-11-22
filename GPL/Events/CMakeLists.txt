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

set(FILEEVENTS_SOURCE_DIR ${CMAKE_CURRENT_SOURCE_DIR})
set(FILEEVENTS_DEPFILE ${CMAKE_CURRENT_BINARY_DIR}/FileEvents.bpf.d)
set(FILEEVENTS_CFLAGS
                -g -O2
                -target bpf
                -MD -MF ${FILEEVENTS_DEPFILE}
                -D__KERNEL__
                -D__TARGET_ARCH_${ARCH_TRUNC}
                -D__${ARCH}__
                -I${LIBBPF_UAPI_INCLUDE_DIR}
                -I${VMLINUX_INCLUDE_DIR}
                -I${FILEEVENTS_SOURCE_DIR}
                -I${CMAKE_SOURCE_DIR}/include)

set(FILEEVENTS_SOURCES ${FILEEVENTS_SOURCE_DIR}/FileEvents.bpf.c)
file(GLOB FILEEVENTS_INCLUDES "${FILEEVENTS_SOURCE_DIR}/*.h")
message(STATUS "Including: ${FILEEVENTS_INCLUDES}")

set(FILEEVENTS_BPF_OUTPUT ${TARGET_EBPF_DIR}/FileEvents.bpf.o)
add_custom_command(OUTPUT ${FILEEVENTS_BPF_OUTPUT}
                  COMMAND ${EBPF_EXTERNAL_ENV_FLAGS} ${CLANG} ${FILEEVENTS_CFLAGS} -c ${FILEEVENTS_SOURCES} -o ${FILEEVENTS_BPF_OUTPUT}
                  DEPENDS libbpf
                  DEPFILE ${FILEEVENTS_DEPFILE}
                  COMMENT "[bpf] building ${FILEEVENTS_BPF_OUTPUT}")

add_custom_target(BPFFileEvents ALL DEPENDS ${TARGET_EBPF_DIR}/FileEvents.bpf.o)

# BPF_PROG_TEST_RUN gtests
add_executable(BPFFileEventsTests BPFFileEventsTests.cpp ${GTEST_MAIN})
set_target_properties(BPFFileEventsTests PROPERTIES RUNTIME_OUTPUT_DIRECTORY ${TARGET_TEST_DIR})
target_include_directories(BPFFileEventsTests PRIVATE 
    "${LIBBPF_UAPI_INCLUDE_DIR}"
    "${TARGET_INCLUDE_DIR}"
    "${GTEST_INCLUDE}")

add_dependencies(BPFFileEventsTests BPFFileEvents)

bpf_skeleton(FileEvents)
add_dependencies(FileEvents_skeleton BPFFileEvents)

target_link_libraries(BPFFileEventsTests ${LIBBPF_LIB} ${LIBELF_LIB} ${GTEST_LIB} -pthread -lz)
add_dependencies(BPFFileEventsTests FileEvents_skeleton libbpf libelf gtest)
