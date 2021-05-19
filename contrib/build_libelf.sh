#!/bin/bash

set -euv

if [ ! -d contrib/elftoolchain/build ]; then
    export MAKEFLAGS="" && export MFLAGS="" && \
        WITH_TESTS=no WITH_BUILD_TOOLS=no WITH_ADDITIONAL_DOCUMENTATION=no WITH_PE=no WITH_ISA=no   \
        bmake -C contrib/elftoolchain
    mkdir -p contrib/elftoolchain/build
    cp contrib/elftoolchain/libelf/libelf.a contrib/elftoolchain/build
    cp contrib/elftoolchain/libelf/libelf.h contrib/elftoolchain/build
    cp contrib/elftoolchain/libelf/gelf.h contrib/elftoolchain/build
    cp contrib/elftoolchain/common/elfdefinitions.h contrib/elftoolchain/build
fi
