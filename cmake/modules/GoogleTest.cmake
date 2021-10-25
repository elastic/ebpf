# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.

set(GTEST_SRC "${PROJECT_SOURCE_DIR}/contrib/googletest/googletest")
set(GTEST_MAIN "${GTEST_SRC}/src/gtest_main.cc")
set(GTEST_INCLUDE "${GTEST_SRC}/include")
set(GTEST_BUILD_DIR "${PROJECT_BINARY_DIR}/gtest-prefix/src/gtest-build")
set(GTEST_LIB "${GTEST_BUILD_DIR}/gtest-all.o")
message(STATUS "[contrib] gtest in '${GTEST_SRC}'")

file(MAKE_DIRECTORY ${GTEST_BUILD_DIR})

set(GTEST_CXXFLAGS -g -Wall -Wextra -pthread)
ExternalProject_Add(
    gtest
    DOWNLOAD_COMMAND ""
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ${CMAKE_CXX_COMPILER} ${GTEST_CXXFLAGS} -I${GTEST_INCLUDE} -I${GTEST_SRC} -c ${GTEST_SRC}/src/gtest-all.cc -o ${GTEST_LIB}
    BUILD_IN_SOURCE 0
    INSTALL_COMMAND ""
    BUILD_BYPRODUCTS ${GTEST_LIB}
)
