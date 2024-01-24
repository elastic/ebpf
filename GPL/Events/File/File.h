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

#include <bpf/bpf_core_read.h>

#include "EbpfEventProto.h"
#include "Helpers.h"

/* struct inode */
DECL_FIELD_OFFSET(inode, __i_atime);
DECL_FIELD_OFFSET(inode, __i_mtime);
DECL_FIELD_OFFSET(inode, __i_ctime);

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

static struct path *path_from_file(struct file *f)
{
    size_t off = bpf_core_field_offset(struct file, f_path);
    return (struct path *)((char *)f + off);
}

static void ebpf_file_info__fill(struct ebpf_file_info *finfo, struct dentry *de)
{
    struct timespec64 ts;

    struct inode *ino = BPF_CORE_READ(de, d_inode);

    finfo->inode = BPF_CORE_READ(ino, i_ino);
    finfo->mode  = BPF_CORE_READ(ino, i_mode);
    finfo->size  = BPF_CORE_READ(ino, i_size);
    finfo->uid   = BPF_CORE_READ(ino, i_uid.val);
    finfo->gid   = BPF_CORE_READ(ino, i_gid.val);

    if (FIELD_OFFSET(inode, __i_atime)) {
        bpf_core_read(&ts, sizeof(ts), (char *)ino + FIELD_OFFSET(inode, __i_atime));
        finfo->atime = ts.tv_sec * NANOSECONDS_IN_SECOND + ts.tv_nsec;
    } else if (bpf_core_field_exists(ino->i_atime)) {
        finfo->atime = BPF_CORE_READ(ino, i_atime.tv_sec) * NANOSECONDS_IN_SECOND +
                       BPF_CORE_READ(ino, i_atime.tv_nsec);
    }

    if (FIELD_OFFSET(inode, __i_mtime)) {
        bpf_core_read(&ts, sizeof(ts), (char *)ino + FIELD_OFFSET(inode, __i_mtime));
        finfo->mtime = ts.tv_sec * NANOSECONDS_IN_SECOND + ts.tv_nsec;
    } else if (bpf_core_field_exists(ino->i_mtime)) {
        finfo->mtime = BPF_CORE_READ(ino, i_mtime.tv_sec) * NANOSECONDS_IN_SECOND +
                       BPF_CORE_READ(ino, i_mtime.tv_nsec);
    }

    if (FIELD_OFFSET(inode, __i_ctime)) {
        bpf_core_read(&ts, sizeof(ts), (char *)ino + FIELD_OFFSET(inode, __i_ctime));
        finfo->ctime = ts.tv_sec * NANOSECONDS_IN_SECOND + ts.tv_nsec;
    } else if (bpf_core_field_exists(ino->i_ctime)) {
        finfo->ctime = BPF_CORE_READ(ino, i_ctime.tv_sec) * NANOSECONDS_IN_SECOND +
                       BPF_CORE_READ(ino, i_ctime.tv_nsec);
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
