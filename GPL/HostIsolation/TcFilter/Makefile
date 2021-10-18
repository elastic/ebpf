# SPDX-License-Identifier: GPL-2.0

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

SHELL = /bin/bash -euo pipefail

CXX ?= g++
LLC ?= llc
CLANG ?= clang


GTEST_SRC ?= ../../../contrib/googletest/googletest
LIBBPF_UAPI := $(abspath ../../../contrib/libbpf/include/uapi)
LIBBPF_BUILD := $(abspath ../../../contrib/libbpf/build)
TEST_INCLUDES := -I$(LIBBPF_UAPI) -I$(LIBBPF_BUILD) -I$(GTEST_SRC)/include
LIBELF_BUILD := $(abspath ../../../contrib/elftoolchain/build)

LDFLAGS := -lpthread -lz -L$(LIBBPF_BUILD) -lbpf -L$(LIBELF_BUILD) -lelf 
CXXFLAGS ?= -g -Wall -Wextra -pthread

TEST_LIBS := 
TEST_FILES ?= $(wildcard *Tests.cpp)

# We never want the stdinc flags in our BPF program, they can contain
# things the eBPF program cannot compile or provide LLVM builtins that we can't use.
NOSTDINC_FLAGS += -nostdinc -isystem $(shell $(CC) -print-file-name=include)

TcFilter.bpf.o: TcFilter.bpf.c $(wildcard %.h) Kerneldefs.h
	$(CLANG) -g -O2 $(NOSTDINC_FLAGS) \
		-I../../../contrib/kernel_hdrs \
		-D__KERNEL__ \
		-D__BPF_TRACING__ \
		-Wno-unused-value \
		-Wno-pointer-sign \
		-Wno-compare-distinct-pointer-types \
		-Wno-gnu-variable-sized-type-not-at-end \
		-Wno-address-of-packed-member \
		-Wno-tautological-compare \
		-fno-asynchronous-unwind-tables \
		-emit-llvm -c $< -o - | $(LLC) -march=bpf -mcpu=v2 -filetype=obj -o $@

.PHONY: clean
clean:
	rm -f TcFilter.bpf.o
	rm -rf _testout

_testout:
	mkdir -p _testout

_testout/gtest-all.o : _testout
	mkdir -p $<
	$(CXX) $(CXXFLAGS) -I$(GTEST_SRC)/include -I$(GTEST_SRC) -c $(GTEST_SRC)/src/gtest-all.cc -o $@

_testout/test: _testout/gtest-all.o
	$(CXX) $(TEST_INCLUDES) $(CXXFLAGS) $(GTEST_SRC)/src/gtest_main.cc $(TEST_FILES) -o $@ $(LDFLAGS)  $<

.PHONY: test
test: _testout/test TcFilter.bpf.o
	$<
