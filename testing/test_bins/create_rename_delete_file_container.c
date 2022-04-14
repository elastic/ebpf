// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

// Does the same set of operations as create_rename_delete_file.c, but in a
// separate mount namespace with an overlayfs filesystem as its root. This
// simulates file accesses in a container to ensure they're picked up
// accurately by our probes.
//
// Overlayfs has a bunch of logic that has the potential to mess with the
// accuracy of our file access probes (see open_with_fake_path function in the
// kernel). This logic is the type of thing that's heavily subject to change
// between kernel versions, so it's absolutely something we want to test across
// multiple kernels.
#define _GNU_SOURCE

#include <errno.h>
#include <ftw.h>
#include <sched.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include "common.h"

#define STACK_SIZE (1024 * 1024)

const char *ovl_upperdir = "/ovl_upperdir";
const char *ovl_lowerdir = "/ovl_lowerdir";
const char *ovl_workdir  = "/ovl_workdir";

const char *ovl_mountpoint = "/ovl_mountpoint";

const char *filename_orig = "foo.txt";
const char *filename_new  = "bar.txt";

static int pivot_root(const char *new_root, const char *put_old)
{
    return syscall(SYS_pivot_root, new_root, put_old);
}

static int do_file_ops()
{
    FILE *f;

    CHECK(f = fopen(filename_orig, "w"), NULL);
    CHECK(fclose(f), EOF);
    CHECK(rename(filename_orig, filename_new), -1);
    CHECK(unlink(filename_new), -1);

    return 0;
}

static int child(void *arg)
{
    char *put_old = "put_old";

    char put_old_root_ns[1024];
    snprintf(put_old_root_ns, sizeof(put_old_root_ns), "%s/%s", ovl_mountpoint, put_old);

    // Create mountpoint, upper,lower and work dirs for our new overlay filesystem
    CHECK(mkdir(ovl_mountpoint, 0700), -1);
    CHECK(mkdir(ovl_upperdir, 0700), -1);
    CHECK(mkdir(ovl_lowerdir, 0700), -1);
    CHECK(mkdir(ovl_workdir, 0700), -1);

    // Mount an overlayfs filesytem on ovl_mountpoint
    char mount_flags[1024];
    snprintf(mount_flags, sizeof(mount_flags), "upperdir=%s,lowerdir=%s,workdir=%s", ovl_upperdir,
             ovl_lowerdir, ovl_workdir);
    CHECK(mount(NULL, ovl_mountpoint, "overlay", 0, mount_flags), -1);

    // Create a directory where the current root will be shifted under the new
    // root
    CHECK(mkdir(put_old_root_ns, 0700), -1);

    // Ensure / in this mount namespace doesn't have shared propagation
    CHECK(mount(NULL, "/", NULL, MS_REC | MS_PRIVATE, NULL), -1);

    CHECK(pivot_root(ovl_mountpoint, put_old_root_ns), -1);

    CHECK(chdir("/"), -1);

    CHECK(umount2(put_old, MNT_DETACH), -1);

    // Now we're fully in a new mount namespace with a new root
    // do a create/rename/delete within it
    CHECK(do_file_ops(), -1);

    return 0;
}

static int rm_file(const char *pathname, const struct stat *sbuf, int typeflag, struct FTW *ftwbuf)
{
    CHECK(remove(pathname), -1);
}

static int rm_recursive(const char *dir)
{
    CHECK(nftw(dir, rm_file, 10, FTW_DEPTH | FTW_MOUNT | FTW_PHYS), -1);
}

int main()
{
    int wstatus, err = 0;
    void *child_stack;
    CHECK(child_stack = mmap(NULL, STACK_SIZE, PROT_READ | PROT_WRITE,
                             MAP_PRIVATE | MAP_ANONYMOUS | MAP_STACK, -1, 0),
          MAP_FAILED);

    pid_t child_pid;
    CHECK(child_pid = clone(child, child_stack + STACK_SIZE, CLONE_NEWNS | SIGCHLD, NULL), -1);

    CHECK(wait(&wstatus), -1);

    if (WEXITSTATUS(wstatus) != 0) {
        fprintf(stderr, "child exited with nonzero status %d, see errors\n", WEXITSTATUS(wstatus));
        err = 1;
        goto cleanup;
    }

    printf("{ \"child_pid\": %d, \"filename_orig\": \"/%s\", \"filename_new\": \"/%s\"}\n",
           child_pid, filename_orig, filename_new);

cleanup:
    // Clean up directories created by child
    CHECK(rm_recursive(ovl_mountpoint), -1);
    CHECK(rm_recursive(ovl_upperdir), -1);
    CHECK(rm_recursive(ovl_lowerdir), -1);
    CHECK(rm_recursive(ovl_workdir), -1);

    return err;
}
