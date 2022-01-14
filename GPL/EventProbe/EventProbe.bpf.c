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

DECL_RELO_FUNC_ARGUMENT(vfs_unlink, dentry);
DECL_RELO_FUNC_RET(vfs_unlink);

SEC("fentry/do_unlinkat")
int BPF_PROG(fentry__do_unlinkat)
{
    struct ebpf_fileevents_tid_state state;
    __builtin_memset(&state, 0, sizeof(struct ebpf_fileevents_tid_state));
    state.state_id = EBPF_FILEEVENTS_TID_STATE_UNLINK;
    ebpf_fileevents_write_state__set(&state);
    return 0;
}

SEC("fentry/mnt_want_write")
int BPF_PROG(fentry__mnt_want_write, struct vfsmount *mnt)
{
    struct ebpf_fileevents_tid_state *state = ebpf_fileevents_write_state__get();
    if (state == NULL)
        goto out;

    struct ebpf_fileevents_unlink_state unlink_state;
    unlink_state.mnt    = mnt;
    state->state.unlink = unlink_state;
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

    struct ebpf_fileevents_tid_state *state = ebpf_fileevents_write_state__get();
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

    struct vfsmount *mnt = state->state.unlink.mnt;
    struct path p;
    p.dentry = de;
    p.mnt    = mnt;
    ebpf_resolve_path_to_string(event->path, &p, task);
    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(sched_process_fork, const struct task_struct *parent, const struct task_struct *child)
{
    if (is_kernel_thread(child))
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

SEC("tp_btf/sched_process_exit")
int BPF_PROG(sched_process_exit, const struct task_struct *task)
{
    if (is_kernel_thread(task))
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
