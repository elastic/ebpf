// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#include <fcntl.h>
#include <inttypes.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/uio.h>
#include <unistd.h>

#include "common.h"

static uint64_t timestamp_ns(struct timespec ts)
{
    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

int main()
{
    const char *filename_orig = "/tmp/foo";
    const char *filename_new  = "/tmp/bar";

    char pid_info[8192];
    gen_pid_info_json(pid_info, sizeof(pid_info));
    int fd;
    struct stat snapshots[6]; // create, rename, chmod, write, writev, truncate

    // create
    CHECK(fd = open(filename_orig, O_WRONLY | O_CREAT | O_TRUNC, 0644), -1);
    CHECK(fstat(fd, &snapshots[0]), -1);

    // rename
    CHECK(rename(filename_orig, filename_new), -1);
    CHECK(fstat(fd, &snapshots[1]), -1);

    // Distinct seconds and nanoseconds catch swapped fields and wrong read widths.
    // Setting timestamps does not emit one of the file-modify events below.
    const struct timespec times[2] = {{1700000000, 123456789}, {1700000001, 987654321}};
    CHECK(futimens(fd, times), -1);

    // modify(permissions)
    CHECK(chmod(filename_new, S_IRWXU | S_IRWXG | S_IRWXO), -1);
    CHECK(fstat(fd, &snapshots[2]), -1);

    // modify(content)
    if (write(fd, "test", 4) != 4) {
        perror("write failed");
        return -1;
    }
    CHECK(fstat(fd, &snapshots[3]), -1);

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
    CHECK(fstat(fd, &snapshots[4]), -1);

    // modify(content)
    CHECK(ftruncate(fd, 0), -1);
    CHECK(fstat(fd, &snapshots[5]), -1);

    close(fd);

    // delete
    CHECK(unlink(filename_new), -1);

    printf("{ \"pid_info\": %s, \"filename_orig\": \"%s\", \"filename_new\": \"%s\", "
           "\"timestamps\": [",
           pid_info, filename_orig, filename_new);
    for (int i = 0; i < 6; i++) {
        printf("%s{\"atime\": %" PRIu64 ", \"mtime\": %" PRIu64 ", \"ctime\": %" PRIu64 "}",
               i ? ", " : "", timestamp_ns(snapshots[i].st_atim),
               timestamp_ns(snapshots[i].st_mtim), timestamp_ns(snapshots[i].st_ctim));
    }
    printf("]}\n");

    return 0;
}
