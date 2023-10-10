// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "Helpers.h"
#include "PathResolver.h"
#include "Varlen.h"

/* tty_write */
DECL_FIELD_OFFSET(iov_iter, __iov);

// Limits on large things we send up as variable length parameters.
//
// These should be kept _well_ under half the size of the event_buffer_map or
// the verifier will be unhappy due to bounds checks. Putting a cap on these
// things also prevents any one process from DoS'ing and filling up the
// ringbuffer with super rapid-fire events.
#define ARGV_MAX 20480
#define ENV_MAX 40960
#define TTY_OUT_MAX 8192

SEC("tp_btf/sched_process_fork")
int BPF_PROG(sched_process_fork, const struct task_struct *parent, const struct task_struct *child)
{
    // Ignore the !is_thread_group_leader(child) case as we want to ignore
    // thread creations in the same thread group.
    //
    // Note that a non-thread-group-leader can perform a fork(2), or a clone(2)
    // (without CLONE_THREAD), in which case the child will be in a new thread
    // group. That is something we want to capture, so we only ignore the
    // !is_thread_group_leader(child) case and not the
    // !is_thread_group_leader(parent) case
    if (!is_thread_group_leader(child) || is_kernel_thread(child))
        goto out;

    struct ebpf_process_fork_event *event = get_event_buffer();
    if (!event)
        goto out;

    event->hdr.type = EBPF_EVENT_PROCESS_FORK;
    event->hdr.ts   = bpf_ktime_get_ns();
    ebpf_pid_info__fill(&event->parent_pids, parent);
    ebpf_pid_info__fill(&event->child_pids, child);
    ebpf_cred_info__fill(&event->creds, parent);

    // Variable length fields
    ebpf_vl_fields__init(&event->vl_fields);
    struct ebpf_varlen_field *field;
    long size;

    // pids_ss_cgroup_path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH);
    size  = ebpf_resolve_pids_ss_cgroup_path_to_string(field->data, child);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    bpf_ringbuf_output(&ringbuf, event, EVENT_SIZE(event), 0);

out:
    return 0;
}

SEC("tp_btf/sched_process_exec")
int BPF_PROG(sched_process_exec,
             const struct task_struct *task,
             pid_t old_pid,
             const struct linux_binprm *binprm)
{
    // Note that we don't ignore the !is_thread_group_leader(task) case here.
    // if a non-thread-group-leader thread performs an execve, it assumes the
    // pid info of the thread group leader, all other threads are terminated,
    // and it performs the exec. Thus a non-thread-group-leader performing an
    // exec is valid and something we want to capture
    if (is_kernel_thread(task))
        goto out;

    struct ebpf_process_exec_event *event = get_event_buffer();
    if (!event)
        goto out;

    event->hdr.type = EBPF_EVENT_PROCESS_EXEC;
    event->hdr.ts   = bpf_ktime_get_ns();

    ebpf_pid_info__fill(&event->pids, task);
    ebpf_cred_info__fill(&event->creds, task);
    ebpf_ctty__fill(&event->ctty, task);

    // Variable length fields
    ebpf_vl_fields__init(&event->vl_fields);
    struct ebpf_varlen_field *field;
    long size;

    // pids ss cgroup path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH);
    size  = ebpf_resolve_pids_ss_cgroup_path_to_string(field->data, task);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // argv
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_ARGV);
    size  = ebpf_argv__fill(field->data, ARGV_MAX, task);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // env
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_ENV);
    size  = ebpf_env__fill(field->data, ENV_MAX, task);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // cwd
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_CWD);
    size  = ebpf_resolve_path_to_string(field->data, &task->fs->pwd, task);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // filename
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_FILENAME);
    size  = read_kernel_str_or_empty_str(field->data, PATH_MAX, binprm->filename);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    bpf_ringbuf_output(&ringbuf, event, EVENT_SIZE(event), 0);

out:
    return 0;
}

// Process exit probe
//
// Note that we aren't using the sched_process_exit tracepoint here as it's
// prone to race conditions. We want to emit an exit event when every single
// thread in a thread group has exited. If we were to try to detect that by
// checking task->signal->live == 0 (i.e. check that there are now 0 running
// threads in the thread group), we would race with a thread exit on another
// CPU decrementing task->signal->live before the BPF program can check if it
// is equal to 0.
//
// Checking group_dead on taskstats_exit to determine if every thread in a
// thread group has exited instead is free of race conditions. taskstats_exit
// is only invoked from do_exit and that function call has been there since
// 2006 (see kernel commit 115085ea0794c0f339be8f9d25505c7f9861d824).
//
// group_dead is the result of an atomic decrement and test operation on
// task->signal->live, so is guaranteed to only be passed into taskstats_exit
// as true once, which signifies the last thread in a thread group exiting.
static int taskstats_exit__enter(const struct task_struct *task, int group_dead)
{
    if (!group_dead || is_kernel_thread(task))
        goto out;

    struct ebpf_process_exit_event *event = get_event_buffer();
    if (!event)
        goto out;

    event->hdr.type = EBPF_EVENT_PROCESS_EXIT;
    event->hdr.ts   = bpf_ktime_get_ns();

    // The exit _status_ is stored in the second byte of task->exit_code
    int exit_code    = BPF_CORE_READ(task, exit_code);
    event->exit_code = (exit_code >> 8) & 0xFF;
    ebpf_pid_info__fill(&event->pids, task);

    // Variable length fields
    ebpf_vl_fields__init(&event->vl_fields);
    struct ebpf_varlen_field *field;
    long size;

    // pids_ss_cgroup_path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH);
    size  = ebpf_resolve_pids_ss_cgroup_path_to_string(field->data, task);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    bpf_ringbuf_output(&ringbuf, event, EVENT_SIZE(event), 0);

out:
    return 0;
}

SEC("fentry/taskstats_exit")
int BPF_PROG(fentry__taskstats_exit, const struct task_struct *task, int group_dead)
{
    return taskstats_exit__enter(task, group_dead);
}

SEC("kprobe/taskstats_exit")
int BPF_KPROBE(kprobe__taskstats_exit, const struct task_struct *task, int group_dead)
{
    return taskstats_exit__enter(task, group_dead);
}

// tracepoint/syscalls/sys_[enter/exit]_[name] tracepoints are not available
// with BTF type information, so we must use a non-BTF tracepoint
SEC("tracepoint/syscalls/sys_exit_setsid")
int tracepoint_syscalls_sys_exit_setsid(struct trace_event_raw_sys_exit *args)
{
    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    if (is_kernel_thread(task))
        goto out;

    if (BPF_CORE_READ(args, ret) < 0)
        goto out;

    struct ebpf_process_setsid_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    event->hdr.type = EBPF_EVENT_PROCESS_SETSID;
    event->hdr.ts   = bpf_ktime_get_ns();

    ebpf_pid_info__fill(&event->pids, task);

    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}

static int commit_creds__enter(struct cred *new)
{
    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    const struct cred *old         = BPF_CORE_READ(task, real_cred);

    // NB: We check for a changed fsuid/fsgid despite not sending it up.  This
    // keeps this implementation in-line with the existing endpoint behaviour
    // for the kprobes/tracefs events implementation.

    if (BPF_CORE_READ(new, uid.val) != BPF_CORE_READ(old, uid.val) ||
        BPF_CORE_READ(new, euid.val) != BPF_CORE_READ(old, euid.val) ||
        BPF_CORE_READ(new, suid.val) != BPF_CORE_READ(old, suid.val) ||
        BPF_CORE_READ(new, fsuid.val) != BPF_CORE_READ(old, fsuid.val)) {

        struct ebpf_process_setuid_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
        if (!event)
            goto out;

        event->hdr.type = EBPF_EVENT_PROCESS_SETUID;
        event->hdr.ts   = bpf_ktime_get_ns();

        ebpf_pid_info__fill(&event->pids, task);

        // The legacy kprobe/tracefs implementation reports the gid even if
        // this is a UID change and vice-versa, so we have new_[r,e]gid fields
        // in a uid change event and vice-versa
        event->new_ruid = BPF_CORE_READ(new, uid.val);
        event->new_euid = BPF_CORE_READ(new, euid.val);
        event->new_rgid = BPF_CORE_READ(new, gid.val);
        event->new_egid = BPF_CORE_READ(new, egid.val);

        bpf_ringbuf_submit(event, 0);
    }

    if (BPF_CORE_READ(new, gid.val) != BPF_CORE_READ(old, gid.val) ||
        BPF_CORE_READ(new, egid.val) != BPF_CORE_READ(old, egid.val) ||
        BPF_CORE_READ(new, sgid.val) != BPF_CORE_READ(old, sgid.val) ||
        BPF_CORE_READ(new, fsgid.val) != BPF_CORE_READ(old, fsgid.val)) {

        struct ebpf_process_setgid_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
        if (!event)
            goto out;

        event->hdr.type = EBPF_EVENT_PROCESS_SETGID;
        event->hdr.ts   = bpf_ktime_get_ns();

        ebpf_pid_info__fill(&event->pids, task);

        event->new_rgid = BPF_CORE_READ(new, gid.val);
        event->new_egid = BPF_CORE_READ(new, egid.val);
        event->new_ruid = BPF_CORE_READ(new, uid.val);
        event->new_euid = BPF_CORE_READ(new, euid.val);

        bpf_ringbuf_submit(event, 0);
    }

out:
    return 0;
}

SEC("fentry/commit_creds")
int BPF_PROG(fentry__commit_creds, struct cred *new)
{
    return commit_creds__enter(new);
}

SEC("kprobe/commit_creds")
int BPF_KPROBE(kprobe__commit_creds, struct cred *new)
{
    return commit_creds__enter(new);
}

#define MAX_NR_SEGS 8

static int output_tty_event(struct ebpf_tty_dev *slave, const void *base, size_t base_len)
{
    struct ebpf_process_tty_write_event *event;
    struct ebpf_varlen_field *field;
    const struct task_struct *task;
    int ret = 0;

    event = get_event_buffer();
    if (!event) {
        ret = 1;
        goto out;
    }

    task                     = (struct task_struct *)bpf_get_current_task();
    event->hdr.type          = EBPF_EVENT_PROCESS_TTY_WRITE;
    event->hdr.ts            = bpf_ktime_get_ns();
    u64 len_cap              = base_len > TTY_OUT_MAX ? TTY_OUT_MAX : base_len;
    event->tty_out_truncated = base_len > TTY_OUT_MAX ? base_len - TTY_OUT_MAX : 0;
    event->tty               = *slave;
    ebpf_pid_info__fill(&event->pids, task);
    ebpf_ctty__fill(&event->ctty, task);
    bpf_get_current_comm(event->comm, TASK_COMM_LEN);

    // Variable length fields
    ebpf_vl_fields__init(&event->vl_fields);

    // tty_out
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_TTY_OUT);
    if (bpf_probe_read_user(field->data, len_cap, base)) {
        ret = 1;
        goto out;
    }

    ebpf_vl_field__set_size(&event->vl_fields, field, len_cap);
    bpf_ringbuf_output(&ringbuf, event, EVENT_SIZE(event), 0);
out:
    return ret;
}

static int tty_write__enter(struct kiocb *iocb, struct iov_iter *from)
{
    if (is_consumer()) {
        goto out;
    }

    struct file *f               = BPF_CORE_READ(iocb, ki_filp);
    struct tty_file_private *tfp = (struct tty_file_private *)BPF_CORE_READ(f, private_data);
    struct tty_struct *tty       = BPF_CORE_READ(tfp, tty);

    // Obtain the real TTY
    //
    // @link: link to another pty (master -> slave and vice versa)
    //
    // https://elixir.bootlin.com/linux/v5.19.9/source/drivers/tty/tty_io.c#L2643
    bool is_master             = false;
    struct ebpf_tty_dev master = {};
    struct ebpf_tty_dev slave  = {};
    if (BPF_CORE_READ(tty, driver, type) == TTY_DRIVER_TYPE_PTY &&
        BPF_CORE_READ(tty, driver, subtype) == PTY_TYPE_MASTER) {
        struct tty_struct *tmp = BPF_CORE_READ(tty, link);
        ebpf_tty_dev__fill(&master, tty);
        ebpf_tty_dev__fill(&slave, tmp);
        is_master = true;
    } else {
        ebpf_tty_dev__fill(&slave, tty);
    }

    if (slave.major == 0 && slave.minor == 0) {
        goto out;
    }

    if ((is_master && !(master.termios.c_lflag & ECHO)) && !(slave.termios.c_lflag & ECHO)) {
        goto out;
    }

    const struct iovec *iov;
    if (FIELD_OFFSET(iov_iter, __iov))
        iov = (const struct iovec *)((char *)from + FIELD_OFFSET(iov_iter, __iov));
    else if (bpf_core_field_exists(from->iov))
        iov = BPF_CORE_READ(from, iov);
    else
        goto out;

    u64 nr_segs = BPF_CORE_READ(from, nr_segs);
    nr_segs     = nr_segs > MAX_NR_SEGS ? MAX_NR_SEGS : nr_segs;

    if (nr_segs == 0) {
        u64 count = BPF_CORE_READ(from, count);
        (void)output_tty_event(&slave, (void *)iov, count);
        goto out;
    }

    for (int seg = 0; seg < nr_segs; seg++) {
        // NOTE(matt): this check needs to be here because the verifier
        // detects an infinite loop otherwise.
        if (seg >= MAX_NR_SEGS)
            goto out;

        struct iovec *cur_iov = (struct iovec *)&iov[seg];
        const char *base      = BPF_CORE_READ(cur_iov, iov_base);
        size_t len            = BPF_CORE_READ(cur_iov, iov_len);

        if (output_tty_event(&slave, base, len)) {
            goto out;
        }
    }

out:
    return 0;
}

SEC("fentry/tty_write")
int BPF_PROG(fentry__tty_write, struct kiocb *iocb, struct iov_iter *from)
{
    return tty_write__enter(iocb, from);
}

SEC("kprobe/tty_write")
int BPF_KPROBE(kprobe__tty_write, struct kiocb *iocb, struct iov_iter *from)
{
    return tty_write__enter(iocb, from);
}
