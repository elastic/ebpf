// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#ifndef EBPF_EVENTPROBE_FILE_H
#define EBPF_EVENTPROBE_FILE_H

#include "vmlinux.h"
#include "vmlinux_extra.h"

#include <bpf/bpf_core_read.h>

#include "EbpfEventProto.h"
#include "Helpers.h"

#define PATH_MAX 4096

// include/uapi/linux/stat.h
#define S_IFMT 00170000
#define S_IFSOCK 0140000
#define S_IFLNK 0120000
#define S_IFREG 0100000
#define S_IFBLK 0060000
#define S_IFDIR 0040000
#define S_IFCHR 0020000
#define S_IFIFO 0010000
#define S_ISUID 0004000
#define S_ISGID 0002000
#define S_ISVTX 0001000

#define S_ISLNK(m) (((m)&S_IFMT) == S_IFLNK)
#define S_ISREG(m) (((m)&S_IFMT) == S_IFREG)
#define S_ISDIR(m) (((m)&S_IFMT) == S_IFDIR)
#define S_ISCHR(m) (((m)&S_IFMT) == S_IFCHR)
#define S_ISBLK(m) (((m)&S_IFMT) == S_IFBLK)
#define S_ISFIFO(m) (((m)&S_IFMT) == S_IFIFO)
#define S_ISSOCK(m) (((m)&S_IFMT) == S_IFSOCK)

#define NANOSECONDS_IN_SECOND 1000000000

/* Bit 31 of i_ctime_nsec tracks multigrain timestamp queries. It is not part
 * of the timestamp (see inode_get_ctime_nsec in include/linux/fs.h).
 */
#define I_CTIME_QUERIED (1U << 31)

static struct path *path_from_file(struct file *f)
{
    size_t off = bpf_core_field_offset(struct file, f_path);
    return (struct path *)((char *)f + off);
}

static void ebpf_file_info__fill(struct ebpf_file_info *finfo, struct dentry *de)
{
    struct inode *ino = BPF_CORE_READ(de, d_inode);

    finfo->inode = BPF_CORE_READ(ino, i_ino);
    finfo->mode  = BPF_CORE_READ(ino, i_mode);
    finfo->size  = BPF_CORE_READ(ino, i_size);
    finfo->uid   = BPF_CORE_READ(ino, i_uid.val);
    finfo->gid   = BPF_CORE_READ(ino, i_gid.val);

    // Reset every timestamp: event_buffer_map is reused between events.
    finfo->atime = finfo->mtime = finfo->ctime = 0;

    // Check each timestamp independently: 6.6 renamed only ctime.
    if (bpf_core_field_exists(ino->i_atime)) {
        finfo->atime = BPF_CORE_READ(ino, i_atime.tv_sec) * NANOSECONDS_IN_SECOND +
                       BPF_CORE_READ(ino, i_atime.tv_nsec);
    } else if (bpf_core_field_exists(struct inode___6_8, __i_atime)) {
        struct inode___6_8 *ino68 = (void *)ino;

        finfo->atime = BPF_CORE_READ(ino68, __i_atime.tv_sec) * NANOSECONDS_IN_SECOND +
                       BPF_CORE_READ(ino68, __i_atime.tv_nsec);
    } else if (bpf_core_field_exists(struct inode___6_11, i_atime_sec) &&
               bpf_core_field_exists(struct inode___6_11, i_atime_nsec)) {
        struct inode___6_11 *ino611 = (void *)ino;

        finfo->atime = BPF_CORE_READ(ino611, i_atime_sec) * NANOSECONDS_IN_SECOND +
                       (u64)BPF_CORE_READ(ino611, i_atime_nsec);
    }

    if (bpf_core_field_exists(ino->i_mtime)) {
        finfo->mtime = BPF_CORE_READ(ino, i_mtime.tv_sec) * NANOSECONDS_IN_SECOND +
                       BPF_CORE_READ(ino, i_mtime.tv_nsec);
    } else if (bpf_core_field_exists(struct inode___6_8, __i_mtime)) {
        struct inode___6_8 *ino68 = (void *)ino;

        finfo->mtime = BPF_CORE_READ(ino68, __i_mtime.tv_sec) * NANOSECONDS_IN_SECOND +
                       BPF_CORE_READ(ino68, __i_mtime.tv_nsec);
    } else if (bpf_core_field_exists(struct inode___6_11, i_mtime_sec) &&
               bpf_core_field_exists(struct inode___6_11, i_mtime_nsec)) {
        struct inode___6_11 *ino611 = (void *)ino;

        finfo->mtime = BPF_CORE_READ(ino611, i_mtime_sec) * NANOSECONDS_IN_SECOND +
                       (u64)BPF_CORE_READ(ino611, i_mtime_nsec);
    }

    if (bpf_core_field_exists(ino->i_ctime)) {
        finfo->ctime = BPF_CORE_READ(ino, i_ctime.tv_sec) * NANOSECONDS_IN_SECOND +
                       BPF_CORE_READ(ino, i_ctime.tv_nsec);
    } else if (bpf_core_field_exists(struct inode___6_8, __i_ctime)) {
        struct inode___6_8 *ino68 = (void *)ino;

        finfo->ctime = BPF_CORE_READ(ino68, __i_ctime.tv_sec) * NANOSECONDS_IN_SECOND +
                       BPF_CORE_READ(ino68, __i_ctime.tv_nsec);
    } else if (bpf_core_field_exists(struct inode___6_11, i_ctime_sec) &&
               bpf_core_field_exists(struct inode___6_11, i_ctime_nsec)) {
        struct inode___6_11 *ino611 = (void *)ino;

        finfo->ctime = BPF_CORE_READ(ino611, i_ctime_sec) * NANOSECONDS_IN_SECOND +
                       (u64)(BPF_CORE_READ(ino611, i_ctime_nsec) & ~I_CTIME_QUERIED);
    }

    if (S_ISREG(finfo->mode)) {
        finfo->type = EBPF_FILE_TYPE_FILE;
    } else if (S_ISDIR(finfo->mode)) {
        finfo->type = EBPF_FILE_TYPE_DIR;
    } else if (S_ISLNK(finfo->mode)) {
        finfo->type = EBPF_FILE_TYPE_SYMLINK;
    } else if (S_ISCHR(finfo->mode)) {
        finfo->type = EBPF_FILE_TYPE_CHARACTER_DEVICE;
    } else if (S_ISBLK(finfo->mode)) {
        finfo->type = EBPF_FILE_TYPE_BLOCK_DEVICE;
    } else if (S_ISFIFO(finfo->mode)) {
        finfo->type = EBPF_FILE_TYPE_NAMED_PIPE;
    } else if (S_ISSOCK(finfo->mode)) {
        finfo->type = EBPF_FILE_TYPE_SOCKET;
    } else {
        finfo->type = EBPF_FILE_TYPE_UNKNOWN;
    }
}

#endif // EBPF_EVENTPROBE_FILE_H
