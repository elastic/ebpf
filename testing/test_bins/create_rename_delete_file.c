// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
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

    int fd;

    // create
    CHECK(fd = open(filename_orig, O_WRONLY | O_CREAT | O_TRUNC, 0644), -1);

    // rename
    CHECK(rename(filename_orig, filename_new), -1);

    // modify(permissions)
    CHECK(chmod(filename_new, S_IRWXU | S_IRWXG | S_IRWXO), -1);

    // modify(content)
    if (write(fd, "test", 4) != 4) {
        perror("write failed");
        return -1;
    }

    // modify(content)
    struct iovec iov[2];
    iov[0].iov_base = "test2";
    iov[0].iov_len  = 5;
    iov[1].iov_base = "test3";
    iov[1].iov_len  = 5;
    if (writev(fd, iov, 2) != 10) {
        perror("writev failed");
        return -1;
    }

    // modify(content)
    CHECK(ftruncate(fd, 0), -1);

    close(fd);

    // delete
    CHECK(unlink(filename_new), -1);

    return 0;
}
