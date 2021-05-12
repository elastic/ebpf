#!/bin/bash

# run 'MAKESYSPATH=<dir> build.sh' to use custom share/mk directory for bmake

set -euv

./contrib/build_libelf.sh
make -C GPL/HostIsolation/TcFilter
make -C non-GPL/TcLoader
make -C non-GPL/HostIsolationMapsUtil
make -C non-GPL/HostIsolation/KprobeConnectHook
