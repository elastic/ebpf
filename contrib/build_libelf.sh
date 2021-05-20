#!/bin/bash

# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.


set -euv

if [ ! -d contrib/elftoolchain/build ]; then
    mkdir -p contrib/elftoolchain/build_obj
    export MAKEFLAGS="" && export MFLAGS="" && \
        WITH_TESTS=no WITH_BUILD_TOOLS=no WITH_ADDITIONAL_DOCUMENTATION=no WITH_PE=no WITH_ISA=no   \
        MAKEOBJDIR=${PWD}/contrib/elftoolchain/build_obj \
        bmake -C contrib/elftoolchain
    mkdir -p contrib/elftoolchain/build
    cp contrib/elftoolchain/build_obj/libelf.a contrib/elftoolchain/build
    cp contrib/elftoolchain/libelf/libelf.h contrib/elftoolchain/build
    cp contrib/elftoolchain/libelf/gelf.h contrib/elftoolchain/build
    cp contrib/elftoolchain/common/elfdefinitions.h contrib/elftoolchain/build
fi
