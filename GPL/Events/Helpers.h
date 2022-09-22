// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#ifndef EBPF_EVENTPROBE_HELPERS_H
#define EBPF_EVENTPROBE_HELPERS_H

#include "EbpfEventProto.h"

const volatile int consumer_pid = 0;

#if BPF_DEBUG_TRACE == 0
#undef bpf_printk
#define bpf_printk(fmt, ...)
#endif

// Compiler barrier, used to prevent compile-time insns reordering and optimizations.
#define barrier() asm volatile("" ::: "memory")

#define DECL_FUNC_ARG(func, arg) const volatile int arg__##func##__##arg##__ = 0;
#define FUNC_ARG_READ(type, func, arg)                                                             \
    ({                                                                                             \
        type _ret;                                                                                 \
        bpf_core_read(&_ret, sizeof(_ret), ctx + arg__##func##__##arg##__);                        \
        _ret;                                                                                      \
    })

/*
 *  Reads the specified argument from struct pt_regs without dereferencing it
 *  (unlike FUNC_ARG_READ_PTREGS) (i.e. we get a  pointer to the argument, not
 *  the argument itself). Note that we first have to read the value in struct
 *  pt_regs into a volatile temporary (_dst). Without this, LLVM can generate
 *  code like the following, which will fail to verify:
 *
 *  r3 = 8                      # The register value we want to read is at offset 8 in the context
 *  r2 = r1                     # r1 = ctx pointer
 *  r2 += r3                    # Increment ctx ptr to register value we're interested in
 *  r3 = *(u64 *)(r2 +0)        # Dereference it (fail)
 *  dereference of modified ctx ptr R2 off=8 disallowed
 *
 *  The verifier disallows dereferencing the context pointer when it's been
 *  modified. This will often happen as an inlining optimization if dst is
 *  immediately passed into a function. We instead want code like the following
 *  to be generated:
 *
 *  r2 = r1                     # r1 = ctx pointer
 *  r3 = *(u64 *)(r2 + 8)       # Dereference it, putting the increment in the dereference insn
 *  ...pass r3 to a function
 */
#define FUNC_ARG_READ_PTREGS_NODEREF(dst, func, arg)                                               \
    ({                                                                                             \
        int ret = 0;                                                                               \
        volatile typeof(dst) _dst;                                                                 \
        switch (arg__##func##__##arg##__) {                                                        \
        case 0:                                                                                    \
            _dst = (typeof(dst))PT_REGS_PARM1(ctx);                                                \
            break;                                                                                 \
        case 1:                                                                                    \
            _dst = (typeof(dst))PT_REGS_PARM2(ctx);                                                \
            break;                                                                                 \
        case 2:                                                                                    \
            _dst = (typeof(dst))PT_REGS_PARM3(ctx);                                                \
            break;                                                                                 \
        case 3:                                                                                    \
            _dst = (typeof(dst))PT_REGS_PARM4(ctx);                                                \
            break;                                                                                 \
        case 4:                                                                                    \
            _dst = (typeof(dst))PT_REGS_PARM5(ctx);                                                \
            break;                                                                                 \
        default:                                                                                   \
            ret = -1;                                                                              \
        };                                                                                         \
        dst = _dst;                                                                                \
        barrier();                                                                                 \
        ret;                                                                                       \
    })

#define FUNC_ARG_READ_PTREGS(dst, func, arg)                                                       \
    ({                                                                                             \
        int ret = 0;                                                                               \
        switch (arg__##func##__##arg##__) {                                                        \
        case 0:                                                                                    \
            bpf_core_read(&dst, sizeof(dst), (void *)PT_REGS_PARM1(ctx));                          \
            break;                                                                                 \
        case 1:                                                                                    \
            bpf_core_read(&dst, sizeof(dst), (void *)PT_REGS_PARM2(ctx));                          \
            break;                                                                                 \
        case 2:                                                                                    \
            bpf_core_read(&dst, sizeof(dst), (void *)PT_REGS_PARM3(ctx));                          \
            break;                                                                                 \
        case 3:                                                                                    \
            bpf_core_read(&dst, sizeof(dst), (void *)PT_REGS_PARM4(ctx));                          \
            break;                                                                                 \
        case 4:                                                                                    \
            bpf_core_read(&dst, sizeof(dst), (void *)PT_REGS_PARM5(ctx));                          \
            break;                                                                                 \
        default:                                                                                   \
            ret = -1;                                                                              \
        };                                                                                         \
        barrier();                                                                                 \
        ret;                                                                                       \
    })

#define DECL_FUNC_RET(func) const volatile int ret__##func##__ = 0;
#define FUNC_RET_READ(type, func)                                                                  \
    ({                                                                                             \
        type _ret;                                                                                 \
        bpf_core_read(&_ret, sizeof(_ret), ctx + ret__##func##__);                                 \
        _ret;                                                                                      \
    })

#define DECL_FUNC_ARG_EXISTS(func, arg) const volatile bool exists__##func##__##arg##__ = false;
#define FUNC_ARG_EXISTS(func, arg) exists__##func##__##arg##__

// From linux/err.h
#define MAX_ERRNO 4095

// From include/linux/tty_driver.h
#define TTY_DRIVER_TYPE_PTY 0x0004
#define PTY_TYPE_MASTER 0x0001

// From include/uapi/asm-generic/termbits.h
#define ICANON 0x00002
#define ECHO 0x00008

static bool IS_ERR_OR_NULL(const void *ptr)
{
    return (!ptr) || (unsigned long)ptr >= (unsigned long)-MAX_ERRNO;
}

// Reimplementation of memset:
//
// This is necessary because __builtin_memset, if passed a large enough size,
// will be converted by LLVM to a call to the _library function_ memset, which
// does not exist in BPF-land. An error that looks like this will be logged at
// compile-time:
//
// error: A call to built-in function 'memset' is not supported.
//
// buf _must_ be declared as volatile, otherwise LLVM will decide to convert
// this entire function to its memset intrinsic (as it does for
// __builtin_memset when passed a large enough size), which will, when passed
// to the BPF backend, be converted into a call to the library function memset,
// and fail for the same reason stated above.
static void memset(volatile char *buf, char data, size_t size)
{
    for (size_t i = 0; i < size; i++)
        buf[i] = data;
}

static void ebpf_argv__fill(char *buf, size_t buf_size, const struct task_struct *task)
{
    unsigned long start, end, size;

    start = BPF_CORE_READ(task, mm, arg_start);
    end   = BPF_CORE_READ(task, mm, arg_end);

    size = end - start;
    size = size > buf_size ? buf_size : size;

    memset(buf, '\0', buf_size);
    bpf_probe_read_user(buf, size, (void *)start);

    // Prevent final arg from being unterminated if buf is too small for args
    buf[buf_size - 1] = '\0';
}

static void ebpf_tty_dev__fill(struct ebpf_tty_dev *tty_dev, const struct tty_struct *tty)
{
    tty_dev->major = BPF_CORE_READ(tty, driver, major);
    tty_dev->minor = BPF_CORE_READ(tty, driver, minor_start);
    tty_dev->minor += BPF_CORE_READ(tty, index);

    struct winsize winsize     = BPF_CORE_READ(tty, winsize);
    struct ebpf_tty_winsize ws = {};
    ws.rows                    = winsize.ws_row;
    ws.cols                    = winsize.ws_col;
    tty_dev->winsize           = ws;

    struct ktermios termios   = BPF_CORE_READ(tty, termios);
    struct ebpf_tty_termios t = {};
    t.c_iflag                 = termios.c_iflag;
    t.c_oflag                 = termios.c_oflag;
    t.c_lflag                 = termios.c_lflag;
    t.c_cflag                 = termios.c_cflag;
    tty_dev->termios          = t;
}

static void ebpf_ctty__fill(struct ebpf_tty_dev *ctty, const struct task_struct *task)
{
    struct tty_struct *tty = BPF_CORE_READ(task, signal, tty);
    ebpf_tty_dev__fill(ctty, tty);
}

static void ebpf_pid_info__fill(struct ebpf_pid_info *pi, const struct task_struct *task)
{
    pi->tid  = BPF_CORE_READ(task, pid);
    pi->tgid = BPF_CORE_READ(task, tgid);
    pi->ppid = BPF_CORE_READ(task, group_leader, real_parent, tgid);
    pi->pgid = BPF_CORE_READ(task, group_leader, signal, pids[PIDTYPE_PGID], numbers[0].nr);
    pi->sid  = BPF_CORE_READ(task, group_leader, signal, pids[PIDTYPE_SID], numbers[0].nr);
    pi->start_time_ns = BPF_CORE_READ(task, group_leader, start_time);
}

static void ebpf_cred_info__fill(struct ebpf_cred_info *ci, const struct task_struct *task)
{
    ci->ruid = BPF_CORE_READ(task, cred, uid.val);
    ci->euid = BPF_CORE_READ(task, cred, euid.val);
    ci->suid = BPF_CORE_READ(task, cred, suid.val);
    ci->rgid = BPF_CORE_READ(task, cred, gid.val);
    ci->egid = BPF_CORE_READ(task, cred, egid.val);
    ci->sgid = BPF_CORE_READ(task, cred, sgid.val);
}

static bool is_kernel_thread(const struct task_struct *task)
{
    // All kernel threads are children of kthreadd, which always has pid 2
    // except on some ancient kernels (2.4x)
    // https://unix.stackexchange.com/a/411175
    return BPF_CORE_READ(task, group_leader, real_parent, tgid) == 2;
}

static bool is_thread_group_leader(const struct task_struct *task)
{
    return BPF_CORE_READ(task, pid) == BPF_CORE_READ(task, tgid);
}

static bool is_consumer()
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    return consumer_pid == pid;
}

#endif // EBPF_EVENTPROBE_HELPERS_H
