// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2026 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

// Writes to the master side of a pseudo terminal, which the tty_write probe
// must recognise as a pty master and report as its slave.

#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <unistd.h>

int main()
{
    // The test VM has no devpts. Mount one unless there already is one, so
    // the host's /dev/pts is left alone when run outside the VM.
    if (access("/dev/pts/ptmx", F_OK) != 0) {
        mkdir("/dev/pts", 0755);
        if (mount("devpts", "/dev/pts", "devpts", 0, "") != 0) {
            perror("mount devpts");
            return 1;
        }
    }

    int master = open("/dev/pts/ptmx", O_RDWR | O_NOCTTY);
    if (master < 0) {
        perror("open ptmx");
        return 1;
    }
    if (unlockpt(master) != 0) {
        perror("unlockpt");
        return 1;
    }
    // Keep the slave open so the write has somewhere to go
    int slave = ioctl(master, TIOCGPTPEER, O_RDWR | O_NOCTTY);
    if (slave < 0) {
        perror("TIOCGPTPEER");
        return 1;
    }

    if (write(master, "--- OK\n", 7) != 7) {
        perror("write");
        return 1;
    }

    printf("{\"pid\": %d}\n", getpid());
    return 0;
}
