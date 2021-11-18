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
include(arch)

set(FILEEVENTS_CFLAGS
                -g -O2
                -target bpf
                -D__TARGET_ARCH_${ARCH_TRUNC}
                -D__${ARCH}__
                -I${LIBBPF_UAPI_INCLUDE_DIR}
                -I${VMLINUX_INCLUDE_DIR})

set(FILEEVENTS_SOURCES ${CMAKE_CURRENT_SOURCE_DIR}/FileEvents.bpf.c)

set(FILEEVENTS_BPF_OUTPUT ${TARGET_EBPF_DIR}/FileEvents.bpf.o)
add_custom_command(OUTPUT ${FILEEVENTS_BPF_OUTPUT}
                  COMMAND ${EBPF_EXTERNAL_ENV_FLAGS} ${CLANG} ${FILEEVENTS_CFLAGS} -c ${FILEEVENTS_SOURCES} -o ${FILEEVENTS_BPF_OUTPUT}
                  DEPENDS libbpf
                  IMPLICIT_DEPENDS C ${FILEEVENTS_SOURCES}
                  COMMENT "[bpf] building ${FILEEVENTS_BPF_OUTPUT}")

add_custom_target(BPFFileEvents ALL DEPENDS ${TARGET_EBPF_DIR}/FileEvents.bpf.o)
