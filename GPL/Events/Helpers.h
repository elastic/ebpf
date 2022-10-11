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
#define ECHO 0x00008

// We can't use the ringbuf reserve/commit API if we want to output an event
// with variable length fields as we won't know the event size in advance, so
// we create events on the event_buffer_map if this is the case and output them
// with bpf_ringbuf_output.
//
// If the event has no variable length parameters (i.e. is always a fixed
// size). bpf_ringbuf_reserve/bpf_ringbuf_submit should be used instead to
// avoid the extra memory copy for better performance.

// 2 MiB per cpu core, ~1MiB is useable as we bail if we go over half
#define EVENT_BUFFER_SIZE (1 << 21)
#define EVENT_BUFFER_SIZE_HALF (EVENT_BUFFER_SIZE >> 1)
#define EVENT_BUFFER_SIZE_HALF_MASK (EVENT_BUFFER_SIZE_HALF - 1)

// Convenience macro to determine the current size of an event with its
// variable length fields
//
// We logical and with (EVENT_BUFFER_SIZE - 1). This puts both an upper and
// lower bound on the value so that we have 0 <= value < EVENT_BUFFER_SIZE, and
// the verifier is happy.
#define EVENT_SIZE(x) ((sizeof(*x) + x->vl_fields.size) & (EVENT_BUFFER_SIZE - 1))

// Using a BPF_MAP_TYPE_PERCPU_ARRAY here would be simpler but unfortunately we
// can't use one. The allocation of map values for a BPF_MAP_TYPE_PERCPU_ARRAY
// is done under the hood by Linux's percpu allocator, which has a maximum
// allocation size of 32 KiB (See PCPU_MIN_UNIT_SIZE in include/linux/percpu.h
// as of Linux 6.0). Trying to create a BPF_MAP_TYPE_PERCPU_ARRAY with a value
// size larger than 32 KiB will result in -ENOMEM.
//
// This is too small for us, so instead we implement a percpu array ourselves
// using a BPF_MAP_TYPE_ARRAY. We resize it in userspace to $(nproc) elements
// and access it through the get_event_buffer helper, which returns the value
// corresponding to the current processor.
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, EVENT_BUFFER_SIZE);
    __uint(max_entries, 0);
} event_buffer_map SEC(".maps");

static void *get_event_buffer()
{
    int key = bpf_get_smp_processor_id();
    return bpf_map_lookup_elem(&event_buffer_map, &key);
}

// Convenience macro to bail out and submit what we've got if we're out of
// variable length field space
//
// If we're already over half the size of the percpu event buffer, this macro
// ensures we never add any further fields. If we do, the &
// EVENT_BUFFER_SIZE_HALF operation below (which is necessary to keep the
// verifier happy) will cause us to overwrite preceeding variable length
// fields, resulting in corrupt data
#define ADD_VL_FIELD_OR_GOTO_EMIT(arg_event, arg_field, arg_type)                                  \
    do {                                                                                           \
        if (EVENT_SIZE(arg_event) >= EVENT_BUFFER_SIZE_HALF) {                                     \
            bpf_printk("Bailing at variable-length field of type %d (event type %d), out of "      \
                       "buffer space",                                                             \
                       arg_type, arg_event->hdr.type);                                             \
            goto emit;                                                                             \
        }                                                                                          \
                                                                                                   \
        struct ebpf_varlen_fields_start *__vlf = &arg_event->vl_fields;                            \
        struct ebpf_varlen_field *__field =                                                        \
            (struct ebpf_varlen_field *)(&__vlf->data[__vlf->size & EVENT_BUFFER_SIZE_HALF_MASK]); \
        __vlf->nfields++;                                                                          \
        __field->type = arg_type;                                                                  \
        arg_field     = __field;                                                                   \
    } while (0)

void ebpf_vl_fields__init(struct ebpf_varlen_fields_start *fields)
{
    fields->nfields = 0;
    fields->size    = 0;
}

void ebpf_vl_field__set_size(struct ebpf_varlen_fields_start *vl_fields,
                             struct ebpf_varlen_field *field,
                             size_t size)
{
    vl_fields->size += size + sizeof(struct ebpf_varlen_field);
    field->size = size;
}

static bool IS_ERR_OR_NULL(const void *ptr)
{
    return (!ptr) || (unsigned long)ptr >= (unsigned long)-MAX_ERRNO;
}

static long ebpf_argv__fill(char *buf, size_t buf_size, const struct task_struct *task)
{
    unsigned long start, end, size;

    start = BPF_CORE_READ(task, mm, arg_start);
    end   = BPF_CORE_READ(task, mm, arg_end);

    size = end - start;
    size = size > buf_size ? buf_size : size;

    bpf_probe_read_user(buf, size, (void *)start);

    // Prevent final arg from being unterminated if buf is too small for args
    buf[buf_size - 1] = '\0';

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
