// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#include <fcntl.h>
#include <stdio.h>
#include <unistd.h>

int main()
{
    int fd = open("/dev/ttyS0", O_RDWR);
    write(fd, "--- OK\n", 7);
    pid_t pid = getpid();
    printf("{\"pid\": %d}\n", pid);
    return 0;
}
