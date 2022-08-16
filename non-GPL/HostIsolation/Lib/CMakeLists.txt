# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

ebpf_static_library(EbpfHostIsolation
    SOURCES TcLoader.c KprobeLoader.c UpdateMaps.c Common.c
    LINK TcFilter KprobeConnectHook libbpf
    PUBLIC_HEADERS TcLoader.h KprobeLoader.h UpdateMaps.h Common.h
    INSTALL
)
