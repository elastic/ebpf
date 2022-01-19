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

#include "Helpers.h"
#include "Maps.h"
#include "PathResolver.h"

char LICENSE[] SEC("license") = "GPL";

enum ebpf_fileevents_tid_state_id {
    EBPF_FILEEVENTS_TID_STATE_UNKNOWN = 0,
    EBPF_FILEEVENTS_TID_STATE_UNLINK  = 1,
};

struct ebpf_fileevents_unlink_state {
    struct vfsmount *mnt;
};
struct ebpf_fileevents_tid_state {
    enum ebpf_fileevents_tid_state_id state_id;
    union {
        struct ebpf_fileevents_unlink_state unlink;
    } state;
};

struct bpf_map_def SEC("maps") elastic_ebpf_fileevents_tid_state = {
    .type        = BPF_MAP_TYPE_LRU_HASH,
    .key_size    = sizeof(u64),
    .value_size  = sizeof(struct ebpf_fileevents_tid_state),
    .max_entries = 4096,
};

static __always_inline struct ebpf_fileevents_tid_state *ebpf_fileevents_write_state__get(void)
{
    u64 tid = bpf_get_current_pid_tgid();
    return bpf_map_lookup_elem(&elastic_ebpf_fileevents_tid_state, &tid);
}

static __always_inline long
ebpf_fileevents_write_state__set(struct ebpf_fileevents_tid_state *state)
{
    u64 tid = bpf_get_current_pid_tgid();
    return bpf_map_update_elem(&elastic_ebpf_fileevents_tid_state, &tid, state, BPF_ANY);
}

// Context relocations: see the fill_ctx_relos in LibEbpfEvents.c
// to see how these are updated from userspace
const volatile int arg__vfs_unlink__dentry__ = 0;

SEC("fentry/do_unlinkat")
int BPF_PROG(fexit__do_unlinkat)
{
    struct ebpf_fileevents_tid_state state;
    __builtin_memset(&state, 0, sizeof(struct ebpf_fileevents_tid_state));
    state.state_id = EBPF_FILEEVENTS_TID_STATE_UNLINK;
    ebpf_fileevents_write_state__set(&state);

    return 0;
}

SEC("fentry/mnt_want_write")
int BPF_PROG(fexit__mnt_want_write, struct vfsmount *mnt)
{
    struct ebpf_fileevents_tid_state *state = ebpf_fileevents_write_state__get();
    if (state == NULL) {
        return 0;
    }

    struct ebpf_fileevents_unlink_state unlink_state;
    unlink_state.mnt    = mnt;
    state->state.unlink = unlink_state;
    return 0;
}

SEC("fexit/vfs_unlink")
int BPF_PROG(fexit__vfs_unlink)
{
    struct dentry *de        = NULL;
    struct task_struct *task = bpf_get_current_task_btf();
    if (is_kernel_thread(task))
        goto out;

    struct ebpf_fileevents_tid_state *state = ebpf_fileevents_write_state__get();
    if (state == NULL) {
        bpf_printk("vfs_unlink: no state\n");
        goto out;
    }

    bpf_core_read(&de, sizeof(unsigned long long), ctx + arg__vfs_unlink__dentry__);

    struct ebpf_file_delete_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

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
