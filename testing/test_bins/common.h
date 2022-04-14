// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#include <stdio.h>
#include <sys/types.h>
#include <syscall.h>
#include <unistd.h>

// Convenience wrapper for glibc error checking
#define CHECK(stmt, err)                                                                           \
    do {                                                                                           \
        if ((stmt) == err) {                                                                       \
            perror(#stmt);                                                                         \
            return -1;                                                                             \
        }                                                                                          \
    } while (0)

// Old toolchain doesn't provide this syscall
pid_t gettid()
{
    return syscall(SYS_gettid);
}

void gen_pid_info_json(char *buf, size_t size)
{
    snprintf(buf, size, "{\"tid\": %d, \"ppid\": %d, \"tgid\": %d, \"sid\": %d, \"pgid\": %d}",
             gettid(), getppid(), getpid(), getsid(0), getpgid(0));
}
