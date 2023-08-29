// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <wait.h>

#include "common.h"

int main()
{
    pid_t pid;
    struct __user_cap_header_struct hdr   = {_LINUX_CAPABILITY_VERSION_3, 0};
    struct __user_cap_data_struct data[2] = {{0}};

    data[0].permitted = 0xffffffff;
    data[1].permitted = 0;
    data[0].effective = 0xf0f0f0f0;
    data[1].effective = 0;
    CHECK(capset(&hdr, &data[0]), -1);

    CHECK(pid = fork(), -1);

    if (pid != 0) {
        int wstatus;
        wait(&wstatus);

        char pid_info[8192];
        gen_pid_info_json(pid_info, sizeof(pid_info));
        printf("{ \"parent_info\": %s, \"child_pid\": %d}\n", pid_info, pid);
    } else {
        char *env_list[] = {"TEST_ENV_KEY1=TEST_ENV_VAL1", "TEST_ENV_KEY2=TEST_ENV_VAL2", NULL};
        CHECK(execle("./do_nothing", "./do_nothing", NULL, env_list), -1);
    }

    return 0;
}
