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
#define NULL 0

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
    struct ebpf_event *event = NULL;
    struct ebpf_event_file_delete_data *edata = NULL;

    if (ret != 0)
        goto out;

    event = ebpf_event__new(&ringbuf, EBPF_EVENT_FILE_DELETE);
    if (!event)
    {
        // todo(fntlnz): fentry cannot return anything but zero, handle error here
        goto out;
    }

    edata = (struct ebpf_event_file_delete_data *)event->data;
    edata->pid = bpf_get_current_pid_tgid() >> 32;

    size_t len = ebpf_event_file_path__from_dentry(&edata->path, dentry);

    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}

SEC("tp_btf/sched_process_fork")
int BPF_PROG(sched_process_fork,
        const struct task_struct *parent,
        const struct task_struct *child)
{
    struct ebpf_event *event = NULL;
    struct ebpf_event_process_fork_data *edata = NULL;

    event = ebpf_event__new(&ringbuf, EBPF_EVENT_PROCESS_FORK);
    if (!event)
        goto out;

    edata = (struct ebpf_event_process_fork_data *)event->data;
    edata->parent_pid = parent->pid;
    edata->child_pid = child->pid;

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
    struct ebpf_event *event = NULL;
    struct ebpf_event_process_exec_data *edata = NULL;

    event = ebpf_event__new(&ringbuf, EBPF_EVENT_PROCESS_EXEC);
    if (!event)
        goto out;

    edata = (struct ebpf_event_process_exec_data *)event->data;
    edata->pid = task->pid;

    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}
