// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#ifndef EBPF_EVENTPROBE_FILE_H
#define EBPF_EVENTPROBE_FILE_H

#include "EbpfEventProto.h"

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

#define S_IRWXU 00700
#define S_IRUSR 00400
#define S_IWUSR 00200
#define S_IXUSR 00100

#define S_IRWXG 00070
#define S_IRGRP 00040
#define S_IWGRP 00020
#define S_IXGRP 00010

#define S_IRWXO 00007
#define S_IROTH 00004
#define S_IWOTH 00002
#define S_IXOTH 00001

static int ebpf_file_info__fill(struct ebpf_file_info *finfo, struct dentry *de)
{
    struct inode *ino = BPF_CORE_READ(de, d_inode);

    finfo->inode = BPF_CORE_READ(ino, i_ino);
    finfo->mode  = BPF_CORE_READ(ino, i_mode);
    finfo->size  = BPF_CORE_READ(ino, i_size);
    finfo->uid   = BPF_CORE_READ(ino, i_uid.val);
    finfo->gid   = BPF_CORE_READ(ino, i_gid.val);
    finfo->mtime = BPF_CORE_READ(ino, i_mtime.tv_nsec);
    finfo->ctime = BPF_CORE_READ(ino, i_ctime.tv_nsec);

    if (S_ISREG(finfo->mode)) {
        finfo->type = EBPF_FILE_TYPE_FILE;
    } else if (S_ISDIR(finfo->mode)) {
        finfo->type = EBPF_FILE_TYPE_DIR;
    } else if (S_ISLNK(finfo->mode)) {
        finfo->type = EBPF_FILE_TYPE_SYMLINK;
    } else {
        bpf_printk("unknown file type (mode=%d)", finfo->mode);
        return -1;
    }

    return 0;
}

#endif // EBPF_EVENTPROBE_FILE_H
