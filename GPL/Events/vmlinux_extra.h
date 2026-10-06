// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2026 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#ifndef EBPF_EVENTPROBE_VMLINUX_EXTRA_H
#define EBPF_EVENTPROBE_VMLINUX_EXTRA_H

#include "vmlinux.h"

/* CO-RE matches inode___* to inode and relocates members by name. These
 * partial definitions describe only the timestamp fields we read.
 * __i_ctime appeared in 6.6; __i_atime and __i_mtime followed in 6.7.
 */
struct inode___6_8 {
    struct timespec64 __i_atime;
    struct timespec64 __i_mtime;
    struct timespec64 __i_ctime;
} __attribute__((preserve_access_index));

/* Linux 6.11 replaced timespec64 fields with s64 seconds and u32 nanoseconds. */
struct inode___6_11 {
    time64_t i_atime_sec;
    time64_t i_mtime_sec;
    time64_t i_ctime_sec;
    u32 i_atime_nsec;
    u32 i_mtime_nsec;
    u32 i_ctime_nsec;
} __attribute__((preserve_access_index));

#endif // EBPF_EVENTPROBE_VMLINUX_EXTRA_H
