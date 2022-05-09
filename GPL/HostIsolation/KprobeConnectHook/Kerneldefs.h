// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

typedef signed char __s8;

typedef unsigned char __u8;

typedef short int __s16;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

typedef __u16 __le16;

typedef __u16 __be16;

typedef __u32 __be32;

typedef __u64 __be64;

typedef __u32 __wsum;

struct in_addr {
    __be32 s_addr;
};

typedef short unsigned int __kernel_sa_family_t;
typedef __kernel_sa_family_t sa_family_t;

struct sockaddr_in {
    __kernel_sa_family_t sin_family;
    __be16 sin_port;
    struct in_addr sin_addr;
    unsigned char __pad[8];
};

struct sockaddr {
    sa_family_t sa_family;
    char sa_data[14];
};

struct pt_regs {
    long unsigned int r15;
    long unsigned int r14;
    long unsigned int r13;
    long unsigned int r12;
    long unsigned int bp;
    long unsigned int bx;
    long unsigned int r11;
    long unsigned int r10;
    long unsigned int r9;
    long unsigned int r8;
    long unsigned int ax;
    long unsigned int cx;
    long unsigned int dx;
    long unsigned int si;
    long unsigned int di;
    long unsigned int orig_ax;
    long unsigned int ip;
    long unsigned int cs;
    long unsigned int flags;
    long unsigned int sp;
    long unsigned int ss;
};

// from aarch64 ptrace.h:
/*
 * User structures for general purpose, floating point and debug registers.
 */
struct user_pt_regs {
    __u64 regs[31];
    __u64 sp;
    __u64 pc;
    __u64 pstate;
};
