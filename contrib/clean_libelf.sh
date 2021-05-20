#!/bin/bash

set -euv

export MAKEFLAGS="" && export MFLAGS="" && \
    WITH_TESTS=no WITH_BUILD_TOOLS=no WITH_ADDITIONAL_DOCUMENTATION=no WITH_PE=no WITH_ISA=no   \
    MAKEOBJDIR=${PWD}/contrib/elftoolchain/build_obj \
    bmake -C contrib/elftoolchain clean
rm -rf contrib/elftoolchain/build
rm -rf contrib/elftoolchain/build_obj
