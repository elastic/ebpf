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


// TODO: Re-enable tty_write probe when BTF issues are fixed
#if 0
/* tty_write */
DECL_FUNC_ARG(tty_write, from);
DECL_FUNC_ARG(tty_write, buf);
DECL_FUNC_ARG(tty_write, count);
DECL_FUNC_ARG_EXISTS(tty_write, from);
#endif

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

    struct ebpf_process_fork_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    event->hdr.type = EBPF_EVENT_PROCESS_FORK;
    event->hdr.ts   = bpf_ktime_get_ns();
    ebpf_pid_info__fill(&event->parent_pids, parent);
    ebpf_pid_info__fill(&event->child_pids, child);
    ebpf_resolve_pids_ss_cgroup_path_to_string(event->pids_ss_cgroup_path, child);

    bpf_ringbuf_submit(event, 0);

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

    struct ebpf_process_exec_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    event->hdr.type = EBPF_EVENT_PROCESS_EXEC;
    event->hdr.ts   = bpf_ktime_get_ns();

    ebpf_pid_info__fill(&event->pids, task);
    ebpf_cred_info__fill(&event->creds, task);
    ebpf_ctty__fill(&event->ctty, task);
    ebpf_argv__fill(event->argv, sizeof(event->argv), task);
    ebpf_resolve_path_to_string(event->cwd, &task->fs->pwd, task);
    ebpf_resolve_pids_ss_cgroup_path_to_string(event->pids_ss_cgroup_path, task);
    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), binprm->filename);

    bpf_ringbuf_submit(event, 0);

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

    struct ebpf_process_exit_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    event->hdr.type = EBPF_EVENT_PROCESS_EXIT;
    event->hdr.ts   = bpf_ktime_get_ns();

    // The exit _status_ is stored in the second byte of task->exit_code
    int exit_code    = BPF_CORE_READ(task, exit_code);
    event->exit_code = (exit_code >> 8) & 0xFF;
    ebpf_pid_info__fill(&event->pids, task);
    ebpf_resolve_pids_ss_cgroup_path_to_string(event->pids_ss_cgroup_path, task);

    bpf_ringbuf_submit(event, 0);

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

    if (args->ret < 0)
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

// TODO: Re-enable tty_write probe when BTF issues are fixed
#if 0
static int tty_write__enter(const char *buf, ssize_t count)
{
    if (is_consumer())
        goto out;

    if (count <= 0)
        goto out;

    struct ebpf_process_tty_write_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    event->hdr.type          = EBPF_EVENT_PROCESS_TTY_WRITE;
    event->hdr.ts            = bpf_ktime_get_ns();
    event->tty_out_len       = count;
    event->tty_out_truncated = count > TTY_OUT_MAX ? 1 : 0;

    const struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ebpf_pid_info__fill(&event->pids, task);

    if (bpf_probe_read_user(event->tty_out, count > TTY_OUT_MAX ? TTY_OUT_MAX : count,
                            (void *)buf)) {
        bpf_printk("tty_write__enter: error reading buf\n");
        bpf_ringbuf_discard(event, 0);
        goto out;
    }

    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}

SEC("fentry/tty_write")
int BPF_PROG(fentry__tty_write)
{
    const char *buf;
    ssize_t count;

    if (FUNC_ARG_EXISTS(tty_write, from)) {
        struct iov_iter *ii = FUNC_ARG_READ(___type(ii), tty_write, from);
        buf                 = BPF_CORE_READ(ii, iov, iov_base);
        count               = BPF_CORE_READ(ii, iov, iov_len);
    } else {
        buf   = FUNC_ARG_READ(___type(buf), tty_write, buf);
        count = FUNC_ARG_READ(___type(count), tty_write, count);
    }

    return tty_write__enter(buf, count);
}

SEC("kprobe/tty_write")
int BPF_KPROBE(kprobe__tty_write)
{
    const char *buf;
    ssize_t count;

    if (FUNC_ARG_EXISTS(tty_write, from)) {
        struct iov_iter ii;
        if (FUNC_ARG_READ_PTREGS(ii, tty_write, from)) {
            bpf_printk("kprobe__tty_write: error reading iov_iter\n");
            goto out;
        }
        buf   = BPF_CORE_READ(ii.iov, iov_base);
        count = BPF_CORE_READ(ii.iov, iov_len);
    } else {
        if (FUNC_ARG_READ_PTREGS(buf, tty_write, buf)) {
            bpf_printk("kprobe__tty_write: error reading buf\n");
            goto out;
        }
        if (FUNC_ARG_READ_PTREGS(count, tty_write, count)) {
            bpf_printk("kprobe__tty_write: error reading count\n");
            goto out;
        }
    }

    return tty_write__enter(buf, count);

out:
    return 0;
}
#endif
