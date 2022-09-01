# SPDX-License-Identifier: Elastic-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.


function(ebpf_gtest_binary target)
    set(options OPTIONAL INSTALL)
    set(multiValueArgs SOURCES LINK DEPENDENCIES)

    cmake_parse_arguments(GTEST_BIN "${options}" ""
        "${multiValueArgs}" ${ARGN})

    set(GTEST_SRC "${PROJECT_SOURCE_DIR}/contrib/googletest/googletest")

    add_executable(
        ${target}
        ${GTEST_BIN_SOURCES}
        ${GTEST_SRC}/src/gtest_main.cc
        ${GTEST_SRC}/src/gtest-all.cc
    )

    set_target_properties(${target} PROPERTIES UNITY_BUILD false)

    # Statically link gtest binaries as some need to run in the multikernel tester
    target_link_libraries(${target} ${GTEST_BIN_LINK} -static)
    target_compile_options(${target} PRIVATE -g -Wall -Wextra -fno-rtti)
    target_link_options(${target} PRIVATE -pthread)
    target_include_directories(${target} PRIVATE ${GTEST_SRC}/include ${GTEST_SRC})

    if (NOT CMAKE_BUILD_TYPE STREQUAL Debug)
        add_custom_command(
            TARGET ${target}
            POST_BUILD
            COMMAND ${STRIP} ${CMAKE_CURRENT_BINARY_DIR}/${target}
            VERBATIM
        )
    endif()

    if (GTEST_BIN_INSTALL)
        install(TARGETS
            ${target}
            RUNTIME DESTINATION ${EBPF_INSTALL_DIR}/bin
        )
    endif()
endfunction()
