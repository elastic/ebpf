# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

add_executable(EventsTrace EventsTrace.c)
add_dependencies(EventsTrace FileEvents_skeleton libbpf libelf)
target_link_libraries(EventsTrace ${LIBBPF_LIB} ${LIBELF_LIB} -lz)
target_include_directories(EventsTrace PRIVATE
    "${CMAKE_SOURCE_DIR}/include/"
    "${CMAKE_SOURCE_DIR}/GPL/Events"
    "${TARGET_INCLUDE_DIR}"
)
