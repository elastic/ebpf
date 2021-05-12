#!/bin/bash

set -u

cat contrib/patch/elftoolchain.patch | patch -p0 -r - --forward -d contrib

set -euv
export MAKEFLAGS="" && export MFLAGS="" && \
    WITH_TESTS=no WITH_BUILD_TOOLS=no WITH_ADDITIONAL_DOCUMENTATION=no WITH_PE=no WITH_ISA=no   \
    bmake -C contrib/elftoolchain clean
rm -rf contrib/elftoolchain/build
