
# SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

# Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
# or more contributor license agreements. Licensed under the Elastic License 2.0;
# you may not use this file except in compliance with the Elastic License 2.0.


set(CLANG "clang")
set(LLC "llc")

execute_process(COMMAND ${CLANG} -print-file-name=include
                OUTPUT_VARIABLE NOSTDINC_INCLUDES ERROR_QUIET OUTPUT_STRIP_TRAILING_WHITESPACE)
