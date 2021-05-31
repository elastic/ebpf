#!/bin/bash

# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.


# run 'MAKESYSPATH=<dir> build.sh' to use custom share/mk directory for bmake

set -euv

./contrib/build_libelf.sh
make -C GPL/HostIsolation/TcFilter BUILD_STATIC_LIB=1
make -C non-GPL/TcLoader BUILD_STATIC_LIB=1
make -C non-GPL/HostIsolationMapsUtil BUILD_STATIC_LIB=1
make -C non-GPL/HostIsolation/KprobeConnectHook BUILD_STATIC_LIB=1

mkdir -p build
mkdir -p temporary_obj_dir
cd temporary_obj_dir
ar x ../contrib/libbpf/build/libbpf.a
ar x ../contrib/elftoolchain/build/libelf.a
cd ..
ar cr build/libeBPF.a non-GPL/HostIsolationMapsUtil/build/UpdateMaps.o \
                      non-GPL/HostIsolation/KprobeConnectHook/build/KprobeLoader.o \
                      non-GPL/TcLoader/build/TcLoader.o \
                      non-GPL/Common/Common.o \
                      temporary_obj_dir/*.o

rm -rf temporary_obj_dir

mkdir -p build/include
cp non-GPL/Common/Common.h build/include
cp non-GPL/HostIsolationMapsUtil/UpdateMaps.h build/include
cp non-GPL/HostIsolation/KprobeConnectHook/KprobeLoader.h build/include
cp non-GPL/TcLoader/TcLoader.h build/include

mkdir -p build/ebpf
cp non-GPL/HostIsolation/KprobeConnectHook/build/KprobeConnectHook.bpf.o build/ebpf
cp GPL/HostIsolation/TcFilter/TcFilter.bpf.o build/ebpf
