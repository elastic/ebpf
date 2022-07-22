# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

add_executable(EventsTrace EventsTrace.c)
add_dependencies(EventsTrace EbpfEvents EventProbe_skeleton libbpf libelf)
target_link_libraries(EventsTrace EbpfEvents)

if (BUILD_STATIC_EVENTSTRACE)
    target_link_libraries(EventsTrace -static)
endif()

target_include_directories(EventsTrace PRIVATE
    "${CMAKE_SOURCE_DIR}/GPL/Events"
)
