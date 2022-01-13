// SPDX-License-Identifier: GPL-2.0

/*
 * Elastic eBPF
 * Copyright 2021 Elasticsearch BV
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
 */
#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "FileEventsHelpers.h"
#include "Helpers.h"
#include "Maps.h"
#include "PathResolver.h"

char LICENSE[] SEC("license") = "GPL";

/* vfs_unlink */
DECL_RELO_FUNC_ARGUMENT(vfs_unlink, dentry);
DECL_RELO_FUNC_RET(vfs_unlink);
/* vfs_rename */
DECL_RELO_FUNC_ARGUMENT(vfs_rename, old_dentry);
DECL_RELO_FUNC_ARGUMENT(vfs_rename, new_dentry);
DECL_RELO_FUNC_RET(vfs_rename);

SEC("fentry/do_unlinkat")
int BPF_PROG(fentry__do_unlinkat)
{
    struct ebpf_fileevents_state state;
    __builtin_memset(&state, 0, sizeof(struct ebpf_fileevents_state));
    ebpf_fileevents_state__set(EBPF_FILEEVENTS_STATE_UNLINK, &state);
    return 0;
}

SEC("fentry/mnt_want_write")
int BPF_PROG(fentry__mnt_want_write, struct vfsmount *mnt)
{
    struct ebpf_fileevents_state *state;

    state = ebpf_fileevents_state__get(EBPF_FILEEVENTS_STATE_UNLINK);
    if (state) {
        state->unlink.mnt = mnt;
        goto out;
    }

    state = ebpf_fileevents_state__get(EBPF_FILEEVENTS_STATE_RENAME);
    if (state) {
        state->rename.mnt  = mnt;
        state->rename.step = RENAME_STATE_MOUNT_SET;
        goto out;
    }

out:
    return 0;
}

SEC("fexit/vfs_unlink")
int BPF_PROG(fexit__vfs_unlink)
{
    int ret = RELO_FENTRY_RET_READ(___type(ret), vfs_unlink);
    if (ret != 0)
        goto out;

    struct dentry *de        = NULL;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct ebpf_fileevents_state *state;
    state = ebpf_fileevents_state__get(EBPF_FILEEVENTS_STATE_UNLINK);
    if (state == NULL) {
        bpf_printk("fexit__vfs_unlink: no state\n");
        goto out;
    }

    de = RELO_FENTRY_ARG_READ(___type(de), vfs_unlink, dentry);

    struct ebpf_file_delete_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event) {
        bpf_printk("fexit__vfs_unlink: failed to reserve event\n");
        goto out;
    }

    event->hdr.type = EBPF_EVENT_FILE_DELETE;
    event->hdr.ts   = bpf_ktime_get_ns();
    ebpf_pid_info__fill(&event->pids, task);

    struct path p;
    p.dentry = de;
    p.mnt    = state->unlink.mnt;
    ebpf_resolve_path_to_string(event->path, &p, task);
    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}

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
SEC("fentry/taskstats_exit")
int BPF_PROG(fentry__taskstats_exit, const struct task_struct *task, int group_dead)
{
    if (!group_dead || is_kernel_thread(task))
        goto out;

    struct ebpf_process_exit_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    event->hdr.type = EBPF_EVENT_PROCESS_EXIT;
    event->hdr.ts   = bpf_ktime_get_ns();

    // The exit _status_ is stored in the second byte of task->exit_code
    event->exit_code = (task->exit_code >> 8) & 0xFF;
    ebpf_pid_info__fill(&event->pids, task);

    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}

// tracepoint/syscalls/sys_[enter/exit]_[name] tracepoints are not available
// with BTF type information, so we must use a non-BTF tracepoint
SEC("tracepoint/syscalls/sys_exit_setsid")
int tracepoint_syscalls_sys_exit_setsid(struct trace_event_raw_sys_exit *args)
{
    const struct task_struct *task = (struct task_struct *)bpf_get_current_task_btf();

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

SEC("fexit/do_filp_open")
int BPF_PROG(fexit__do_filp_open,
             int dfd,
             struct filename *pathname,
             const struct open_flags *op,
             struct file *ret)
{
    /*
    'ret' fields such f_mode and f_path should be obtained via BPF_CORE_READ
    because there's a kernel bug that causes a panic.
    Read more: github.com/torvalds/linux/commit/588a25e92458c6efeb7a261d5ca5726f5de89184
    */
    if (IS_ERR_OR_NULL(ret))
        goto out;

    fmode_t fmode = BPF_CORE_READ(ret, f_mode);
    if (fmode & (fmode_t)0x100000) // FMODE_CREATED
    {
        struct ebpf_file_create_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
        if (!event)
            goto out;

        event->hdr.type = EBPF_EVENT_FILE_CREATE;
        event->hdr.ts   = bpf_ktime_get_ns();

        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        ebpf_resolve_path_to_string(event->path, &ret->f_path, task);
        ebpf_pid_info__fill(&event->pids, task);

        bpf_ringbuf_submit(event, 0);
    }

out:
    return 0;
}

SEC("fentry/do_renameat2")
int BPF_PROG(fentry__do_renameat2)
{
    struct ebpf_fileevents_state state = {};
    state.rename.step                  = RENAME_STATE_INIT;
    ebpf_fileevents_state__set(EBPF_FILEEVENTS_STATE_RENAME, &state);
    return 0;
}

SEC("fentry/vfs_rename")
int BPF_PROG(fentry__vfs_rename)
{
    struct ebpf_fileevents_state *state;
    state = ebpf_fileevents_state__get(EBPF_FILEEVENTS_STATE_RENAME);
    if (!state || state->rename.step != RENAME_STATE_MOUNT_SET) {
        bpf_printk("fentry__vfs_rename: state missing or incomplete\n");
        goto out;
    }

    struct dentry *old_dentry, *new_dentry;
    if (bpf_core_type_exists(struct renamedata)) {
        /* Function arguments have been refactored into struct renamedata */
        struct renamedata *rd = (struct renamedata *)ctx[0];
        old_dentry            = rd->old_dentry;
        new_dentry            = rd->new_dentry;
    } else {
        /* Dentries are accessible from ctx */
        old_dentry = RELO_FENTRY_ARG_READ(___type(old_dentry), vfs_rename, old_dentry);
        new_dentry = RELO_FENTRY_ARG_READ(___type(new_dentry), vfs_rename, new_dentry);
    }

    enum ebpf_fileevents_scratch_key key = EBPF_FILEEVENTS_SCRATCH_KEY_RENAME;
    struct ebpf_fileevents_scratch_state *s_state =
        bpf_map_lookup_elem(&elastic_ebpf_fileevents_scratch_state, &key);
    if (!s_state) // This is never the case as it's a percpu-array.
        goto out;

    struct task_struct *task = (struct task_struct*) bpf_get_current_task();

    struct path p;
    p.mnt    = state->rename.mnt;
    p.dentry = old_dentry;
    ebpf_resolve_path_to_string(s_state->rename.old_path, &p, task);
    p.dentry = new_dentry;
    ebpf_resolve_path_to_string(s_state->rename.new_path, &p, task);

    state->rename.step = RENAME_STATE_PATHS_SET;

out:
    return 0;
}

SEC("fexit/vfs_rename")
int BPF_PROG(fexit__vfs_rename)
{
    int ret = RELO_FENTRY_RET_READ(___type(ret), vfs_rename);
    if (ret)
        goto out;

    struct ebpf_fileevents_state *state;
    state = ebpf_fileevents_state__get(EBPF_FILEEVENTS_STATE_RENAME);
    if (!state || state->rename.step != RENAME_STATE_PATHS_SET) {
        bpf_printk("fexit__vfs_rename: state missing or incomplete\n");
        goto out;
    }

    enum ebpf_fileevents_scratch_key key = EBPF_FILEEVENTS_SCRATCH_KEY_RENAME;
    struct ebpf_fileevents_scratch_state *s_state =
        bpf_map_lookup_elem(&elastic_ebpf_fileevents_scratch_state, &key);
    if (!s_state) // This is never the case as it's a percpu-array.
        goto out;

    struct ebpf_file_rename_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    struct task_struct *task = (struct task_struct*) bpf_get_current_task();

    event->hdr.type = EBPF_EVENT_FILE_RENAME;
    event->hdr.ts   = bpf_ktime_get_ns();
    ebpf_pid_info__fill(&event->pids, task);
    bpf_probe_read_str(event->old_path, PATH_MAX_BUF, s_state->rename.old_path);
    bpf_probe_read_str(event->new_path, PATH_MAX_BUF, s_state->rename.new_path);

    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}
