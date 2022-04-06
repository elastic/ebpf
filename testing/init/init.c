// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#define _GNU_SOURCE

#include <fcntl.h>
#include <ftw.h>
#include <libgen.h>
#include <stdio.h>
#include <string.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <unistd.h>

// Convenience wrapper for glibc error checking
#define CHECK(stmt, err)                                                                           \
    do {                                                                                           \
        if ((stmt) == err) {                                                                       \
            perror(#stmt);                                                                         \
            return -1;                                                                             \
        }                                                                                          \
    } while (0)

const char *test_infra_dir = "/test_infra";
const char *new_root       = "/new_root";

static int banner()
{
    struct utsname utsbuf;
    CHECK(uname(&utsbuf), -1);

    printf("      ___                    __                       __  __                 ___\n");
    printf("     /\\_ \\                  /\\ \\__  __               / / /\\ \\              "
           "/'___\\\n");
    printf("   __\\//\\ \\      __      ___\\ \\ ,_\\/\\_\\    ___      / /__\\ \\ \\____  _____ "
           "/\\ \\__/\n");
    printf(" /'__`\\\\ \\ \\   /'__`\\   /',__\\ \\ \\/\\/\\ \\  /'___\\   / /'__`\\ \\ '__`\\/\\ "
           "'__`\\ \\ ,__\\\n");
    printf("/\\  __/ \\_\\ \\_/\\ \\_\\.\\_/\\__, `\\ \\ \\_\\ \\ \\/\\ \\__/  / /\\  __/\\ \\ "
           "\\_\\ \\ \\ \\_\\ \\ \\ \\_/\n");
    printf("\\ \\____\\/\\____\\ \\__/.\\_\\/\\____/\\ \\__\\\\ \\_\\ \\____\\/_/\\ \\____\\\\ "
           "\\_,__/\\ \\ ,__/\\ \\_\\\n");
    printf(" \\/____/\\/____/\\/__/\\/_/\\/___/  \\/__/ \\/_/\\/____/_/  \\/____/ \\/___/  \\ \\ "
           "\\/  \\/_/\n");
    printf("                                                                      \\ \\_\\\n");
    printf("                                                                       \\/_/\n");
    printf("[init] Elastic multi-kernel checker for BPF probes\n");
    printf("[init] This is kernel %s %s (%s) %s\n", utsbuf.sysname, utsbuf.release, utsbuf.version,
           utsbuf.machine);

    return 0;
}

static int
cp_test_infra_file(const char *pathname, const struct stat *sbuf, int typeflag, struct FTW *ftwbuf)
{
    int src_fd, dst_fd;
    char dst_path[4096];
    char pathname_cpy[4096];
    char *file_name;

    // The new and old roots are different filesystems, thus we can't do a
    // simple rename(2) to move the test utilities over. We have to actually
    // open each file and do a read(2)/write(2) on each one to move them to the
    // new root fs.

    if (typeflag != FTW_F)
        return 0; // Ignore all but regular files

    // man 3 basename -- basename may modify it's input string so copy it
    strncpy(pathname_cpy, pathname, sizeof(pathname_cpy));
    file_name = basename(pathname_cpy);

    snprintf(dst_path, sizeof(dst_path), "%s/%s", new_root, file_name);
    CHECK(src_fd = open(pathname, O_RDONLY), -1);
    CHECK(dst_fd = open(dst_path, O_CREAT | O_WRONLY, S_IRWXU), -1);

    printf("[init] copying %s\n", pathname, dst_path);

    while (1) {
        size_t n;
        char buf[4096];
        CHECK(n = read(src_fd, buf, sizeof(buf)), -1);
        if (n == 0)
            break; // EOF, done

        CHECK(write(dst_fd, buf, n), -1);
    }

    CHECK(close(src_fd), -1);
    CHECK(close(dst_fd), -1);
    return 0;
}

static int cp_test_infra()
{
    CHECK(nftw(test_infra_dir, cp_test_infra_file, 10, FTW_DEPTH | FTW_MOUNT | FTW_PHYS), -1);
}

static int setup_pseudo_filesystems()
{
    CHECK(mkdir("/dev", 0755), -1);
    CHECK(mount(NULL, "/dev", "devtmpfs", 0, NULL), -1);

    CHECK(mkdir("/proc", 0755), -1);
    CHECK(mount(NULL, "/proc", "proc", 0, NULL), -1);

    CHECK(mkdir("/tmp", 0755), -1);
    CHECK(mount(NULL, "/tmp", "tmpfs", 0, NULL), -1);

    CHECK(mkdir("/sys", 0755), -1);
    CHECK(mount(NULL, "/sys", "sysfs", 0, NULL), -1);

    CHECK(mount(NULL, "/sys/kernel/debug", "debugfs", 0, NULL), -1);
    CHECK(mount(NULL, "/sys/fs/bpf", "bpf", 0, NULL), -1);

    return 0;
}

int main()
{
    CHECK(banner(), -1);

    // Mount /new_root as a tmpfs, this will be our new /, replacing rootfs
    printf("[init] creating a tmpfs mount at %s\n", new_root);
    CHECK(mkdir(new_root, 0700), -1);
    CHECK(mount(NULL, new_root, "tmpfs", 0, NULL), -1);

    // Copy all test infrastructure to the new root
    printf("[init] copying all test utilities to %s\n", new_root);
    CHECK(cp_test_infra(), -1);

    // Make new_root the new /
    printf("[init] pivot_root'ing to %s and chdir(\"/\")\n", new_root);
    CHECK(chdir(new_root), -1);
    CHECK(mount(new_root, "/", NULL, MS_MOVE, NULL), -1);
    CHECK(chroot("."), -1);
    CHECK(chdir("/"), -1);

    // Mount /proc and friends, everything needed for the testrunner to work
    printf("[init] mounting pseudo-filesystems needed by tests\n", new_root);
    CHECK(setup_pseudo_filesystems(), -1);

    // Exec testrunner
    printf("[init] exec'ing testrunner at /testrunner\n");
    CHECK(execl("/testrunner", "/testrunner", NULL), -1);

    return -1;
}
