// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"

int main()
{
    const char *filename_orig = "/tmp/foo";
    const char *filename_new  = "/tmp/bar";

    char pid_info[8192];
    gen_pid_info_json(pid_info, sizeof(pid_info));
    printf("{ \"pid_info\": %s, \"filename_orig\": \"%s\", \"filename_new\": \"%s\"}\n", pid_info,
           filename_orig, filename_new);

    FILE *f;
    CHECK(f = fopen(filename_orig, "w"), NULL);

    CHECK(fclose(f), EOF);
    CHECK(rename(filename_orig, filename_new), -1);
    CHECK(chmod(filename_new, S_IRWXU | S_IRWXG | S_IRWXO), -1);
    CHECK(unlink(filename_new), -1);

    return 0;
}
