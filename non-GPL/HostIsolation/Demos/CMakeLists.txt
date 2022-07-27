# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.
function(add_demo name)
    add_executable("${name}" "${name}.c")
    target_include_directories(${name} PRIVATE
        "${LIBBPF_TARGET_INCLUDE_DIR}"
        "${LIBBPF_UAPI_INCLUDE_DIR}"
        "${LIBBPF_INCLUDE_DIR}"
        "${PROJECT_SOURCE_DIR}/non-GPL/HostIsolation/Lib")
    target_link_libraries("${name}" PRIVATE HostIsolation)
endfunction()

add_demo(TcLoaderDemo)
add_demo(UpdateIPsDemo)
add_demo(UpdatePidsDemo)
add_demo(KprobeConnectHookDemo)
