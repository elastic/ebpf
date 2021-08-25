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

SHELL = /bin/bash

CXX ?= clang++
LLC ?= llc
CLANG ?= clang


GTEST_SRC ?= ../../../contrib/googletest/googletest
LIBBPF_BUILD := $(abspath ../../../contrib/libbpf/build)
TEST_INCLUDES := -I$(LIBBPF_BUILD) -I$(GTEST_SRC)/include
LIBELF_BUILD := $(abspath ../../../contrib/elftoolchain/build)

LDFLAGS := -lpthread -lz -L$(LIBBPF_BUILD) -lbpf -L$(LIBELF_BUILD) -lelf 
CXXFLAGS ?= -g -Wall -Wextra -pthread

TEST_LIBS := 
TEST_FILES ?= $(wildcard *Test.cpp)

TcFilter.bpf.o: TcFilter.bpf.c $(wildcard %.h) Kerneldefs.h
	$(CLANG) -g -O2 -I../../../contrib/kernel_hdrs -emit-llvm -c $< -o - | $(LLC) -march=bpf -mcpu=v2 -filetype=obj -o $@

.PHONY: clean
clean:
	rm -f TcFilter.bpf.o
	rm -rf _testout

_testout:
	mkdir -p _testout

_testout/gtest-all.o : _testout
	mkdir -p $<
	$(CXX) $(CXXFLAGS) -I$(GTEST_SRC)/include -I$(GTEST_SRC) $(CXXFLAGS) -c $(GTEST_SRC)/src/gtest-all.cc -o $@

_testout/test: _testout/gtest-all.o
	$(CXX) $(TEST_INCLUDES) $(CXXFLAGS) $(GTEST_SRC)/src/gtest_main.cc $(TEST_FILES) -o $@ $(LDFLAGS)  $<

.PHONY: test
test: _testout/test TcFilter.bpf.o
	$<
