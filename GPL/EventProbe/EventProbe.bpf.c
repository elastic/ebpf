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
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "Maps.h"
#include "Helpers.h"

char LICENSE[] SEC("license") = "GPL";

SEC("fexit/security_path_unlink")
int BPF_PROG(security_path_unlink_exit, const struct path *dir, struct dentry *dentry, long ret)
{
    struct task_struct *task = bpf_get_current_task_btf();
    if (is_kernel_thread(task))
        goto out;

    struct ebpf_file_delete_event *event =
        bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    event->hdr.type = EBPF_EVENT_FILE_DELETE;
    event->hdr.ts = bpf_ktime_get_ns();
    ebpf_pid_info__fill(&event->pids, task);
    ebpf_file_path__from_dentry(&event->path, dentry);

    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(sched_process_fork,
        const struct task_struct *parent,
        const struct task_struct *child)
{
    if (is_kernel_thread(child))
        goto out;

    struct ebpf_process_fork_event *event =
        bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    event->hdr.type = EBPF_EVENT_PROCESS_FORK;
    event->hdr.ts = bpf_ktime_get_ns();
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

    struct ebpf_process_exec_event *event =
    bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    event->hdr.type = EBPF_EVENT_PROCESS_EXEC;
    event->hdr.ts = bpf_ktime_get_ns();

    ebpf_pid_info__fill(&event->pids, task);
    ebpf_ctty__fill(&event->ctty, task);
    ebpf_argv__fill(event->argv, sizeof(event->argv), task);
    bpf_probe_read_kernel_str(event->filename, sizeof(event->filename), binprm->filename);

    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}
