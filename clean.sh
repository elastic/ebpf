#!/bin/bash

# run 'MAKESYSPATH=<dir> build.sh' to use custom share/mk directory for bmake

set -euv

./contrib/clean_libelf.sh
make -C GPL/HostIsolation/TcFilter clean
make -C non-GPL/TcLoader clean
make -C non-GPL/HostIsolationMapsUtil clean
make -C non-GPL/HostIsolation/KprobeConnectHook clean
rm -rf build
