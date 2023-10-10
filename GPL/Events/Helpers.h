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
 *  Reads the specified argument from struct pt_regs without dereferencing it. Note that
 *  we first have to read the value in struct pt_regs into a volatile temporary (_dst).
 *  Without this, LLVM can generate code like the following, which will fail to verify:
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
#define FUNC_ARG_READ_PTREGS(dst, func, arg)                                                       \
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

#define DECL_FUNC_RET(func) const volatile int ret__##func##__ = 0;
#define FUNC_RET_READ(type, func)                                                                  \
    ({                                                                                             \
        type _ret;                                                                                 \
        bpf_core_read(&_ret, sizeof(_ret), ctx + ret__##func##__);                                 \
        _ret;                                                                                      \
    })

#define DECL_FUNC_ARG_EXISTS(func, arg) const volatile bool exists__##func##__##arg##__ = false;
#define FUNC_ARG_EXISTS(func, arg) exists__##func##__##arg##__

#define DECL_FIELD_OFFSET(struct, field) const volatile int off__##struct##__##field##__ = 0;
#define FIELD_OFFSET(struct, field) off__##struct##__##field##__

// From linux/err.h
#define MAX_ERRNO 4095

// From include/linux/tty_driver.h
#define TTY_DRIVER_TYPE_PTY 0x0004
#define PTY_TYPE_MASTER 0x0001

// From include/uapi/asm-generic/termbits.h
#define ECHO 0x00008

static bool IS_ERR_OR_NULL(const void *ptr)
{
    return (!ptr) || (unsigned long)ptr >= (unsigned long)-MAX_ERRNO;
}

// Wrapper around bpf_probe_read_kernel_str that reads an empty string upon a read failure
static long read_kernel_str_or_empty_str(void *dst, int size, const void *unsafe_ptr)
{
    long ret = bpf_probe_read_kernel_str(dst, size, unsafe_ptr);
    if (ret < 0) {
        ((char *)dst)[0] = '\0';
        return 1;
    }

    return ret;
}

static long ebpf_argv__fill(char *buf, size_t buf_size, const struct task_struct *task)
{
    unsigned long start, end, size;

    start = BPF_CORE_READ(task, mm, arg_start);
    end   = BPF_CORE_READ(task, mm, arg_end);

    if (end <= start) {
        buf[0] = '\0';
        return 1;
    }

    size = end - start;
    size = size > buf_size ? buf_size : size;

    bpf_probe_read_user(buf, size, (void *)start);

    // Prevent final arg from being unterminated if buf is too small for args
    buf[size - 1] = '\0';

    return size;
}

static long ebpf_env__fill(char *buf, size_t buf_size, const struct task_struct *task)
{
    unsigned long start, end, size;

    start = BPF_CORE_READ(task, mm, env_start);
    end   = BPF_CORE_READ(task, mm, env_end);

    if (end <= start) {
        buf[0] = '\0';
        return 1;
    }

    size = end - start;
    size = size > buf_size ? buf_size : size;

    bpf_probe_read_user(buf, size, (void *)start);

    // Prevent final env from being unterminated if buf is too small for envs
    buf[size - 1] = '\0';

    return size;
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

    // This check is to determine when the kernel_cap_t definition changed.
    //
    // Previously it was:
    // typedef struct kernel_cap_struct {
    //    __u32 cap[_KERNEL_CAPABILITY_U32S];
    // } kernel_cap_t;
    //
    // Currently it is:
    // typedef struct { u64 val; } kernel_cap_t;
    //
    // See https://github.com/torvalds/linux/commit/f122a08b197d076ccf136c73fae0146875812a88
    //
    if (bpf_core_field_exists(task->cred->cap_permitted.cap)) {
        kernel_cap_t dest;

        dest.cap[0]       = 0;
        dest.cap[1]       = 0;
        dest              = BPF_CORE_READ(task, cred, cap_permitted);
        ci->cap_permitted = (((u64)dest.cap[1]) << 32) + dest.cap[0];

        dest.cap[0]       = 0;
        dest.cap[1]       = 0;
        dest              = BPF_CORE_READ(task, cred, cap_effective);
        ci->cap_effective = (((u64)dest.cap[1]) << 32) + dest.cap[0];
    } else {
        const struct cred *cred = BPF_CORE_READ(task, cred);
        const void *cap         = NULL;

        struct new_kernel_cap_struct {
            u64 val;
        } dest;

        dest.val = 0;
        cap      = &cred->cap_permitted;
        bpf_core_read(&dest, sizeof(struct new_kernel_cap_struct), cap);
        ci->cap_permitted = dest.val;

        dest.val = 0;
        cap      = &cred->cap_effective;
        bpf_core_read(&dest, sizeof(struct new_kernel_cap_struct), cap);
        ci->cap_effective = dest.val;
    }
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
