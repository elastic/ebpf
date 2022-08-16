# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

function(add_demo name)
    ebpf_static_binary(${name}
        SOURCES ${name}.c
        LINK EbpfHostIsolation libbpf
        INSTALL
    )
endfunction()

add_demo(TcLoaderDemo)
add_demo(UpdateIPsDemo)
add_demo(UpdatePidsDemo)
add_demo(KprobeConnectHookDemo)
