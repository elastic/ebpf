// SPDX-License-Identifier: GPL-2.0-only

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or
 * FITNESS FOR A PARTICULAR PURPOSE. See the GNU General Public License for
 * more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51
 * Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "Helpers.h"
#include "PathResolver.h"

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
    ebpf_resolve_kernfs_node_to_string(event->pids_ss_cgroup_path, child);

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
    ebpf_resolve_kernfs_node_to_string(event->pids_ss_cgroup_path, task);
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
    ebpf_resolve_kernfs_node_to_string(event->pids_ss_cgroup_path, task);

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
