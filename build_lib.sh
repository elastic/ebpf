#!/bin/bash

# run 'MAKESYSPATH=<dir> build.sh' to use custom share/mk directory for bmake

set -euv

./contrib/build_libelf.sh
make -C GPL/HostIsolation/TcFilter BUILD_STATIC_LIB=1
make -C non-GPL/TcLoader BUILD_STATIC_LIB=1
make -C non-GPL/HostIsolationMapsUtil BUILD_STATIC_LIB=1
make -C non-GPL/HostIsolation/KprobeConnectHook BUILD_STATIC_LIB=1

mkdir -p build
ar cr build/libeBPF.a non-GPL/HostIsolationMapsUtil/build/UpdateMaps.o \
                      non-GPL/HostIsolation/KprobeConnectHook/build/KprobeLoader.o \
                      non-GPL/TcLoader/build/TcLoader.o

mkdir -p build/include
cp non-GPL/Common/Common.h build/include
cp non-GPL/HostIsolationMapsUtil/UpdateMaps.h build/include
cp non-GPL/HostIsolation/KprobeConnectHook/KprobeLoader.h build/include
cp non-GPL/TcLoader/TcLoader.h build/include

mkdir -p build/ebpf
cp non-GPL/HostIsolation/KprobeConnectHook/build/KprobeConnectHook.bpf.o build/ebpf
cp GPL/HostIsolation/TcFilter/TcFilter.bpf.o build/ebpf
