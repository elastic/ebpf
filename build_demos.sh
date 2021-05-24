#!/bin/bash

# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.


# run 'MAKESYSPATH=<dir> build.sh' to use custom share/mk directory for bmake

set -euv

./contrib/build_libelf.sh
make -C GPL/HostIsolation/TcFilter
make -C non-GPL/TcLoader
make -C non-GPL/HostIsolationMapsUtil
make -C non-GPL/HostIsolation/KprobeConnectHook
