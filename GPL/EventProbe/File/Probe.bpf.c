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
#include "State.h"

/* vfs_unlink */
DECL_FUNC_ARG(vfs_unlink, dentry);
DECL_FUNC_RET(vfs_unlink);
/* vfs_rename */
DECL_FUNC_ARG(vfs_rename, old_dentry);
DECL_FUNC_ARG(vfs_rename, new_dentry);
DECL_FUNC_RET(vfs_rename);
DECL_FUNC_ARG_EXISTS(vfs_rename, rd);

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
    struct ebpf_fileevents_state *state = NULL;

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
    int ret = FUNC_RET_READ(___type(ret), vfs_unlink);
    if (ret != 0)
        goto out;

    struct dentry *de        = NULL;
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct ebpf_fileevents_state *state = NULL;
    state                               = ebpf_fileevents_state__get(EBPF_FILEEVENTS_STATE_UNLINK);
    if (state == NULL) {
        bpf_printk("fexit__vfs_unlink: no state\n");
        goto out;
    }

    de = FUNC_ARG_READ(___type(de), vfs_unlink, dentry);

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
    struct ebpf_fileevents_state state = {.rename = {.step = RENAME_STATE_INIT}};
    ebpf_fileevents_state__set(EBPF_FILEEVENTS_STATE_RENAME, &state);

    u32 zero = 0;
    struct ebpf_fileevents_scratch_space *ss =
        bpf_map_lookup_elem(&elastic_ebpf_fileevents_init_buffer, &zero);
    if (!ss)
        goto out;
    ebpf_fileevents_scratch_space__set(EBPF_FILEEVENTS_STATE_RENAME, ss);

out:
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
    if (FUNC_ARG_EXISTS(vfs_rename, rd)) {
        /* Function arguments have been refactored into struct renamedata */
        struct renamedata *rd = (struct renamedata *)ctx[0];
        old_dentry            = rd->old_dentry;
        new_dentry            = rd->new_dentry;
    } else {
        /* Dentries are accessible from ctx */
        old_dentry = FUNC_ARG_READ(___type(old_dentry), vfs_rename, old_dentry);
        new_dentry = FUNC_ARG_READ(___type(new_dentry), vfs_rename, new_dentry);
    }

    struct ebpf_fileevents_scratch_space *ss =
        ebpf_fileevents_scratch_space__get(EBPF_FILEEVENTS_STATE_RENAME);
    if (!ss) {
        bpf_printk("fentry__vfs_rename: scratch space missing\n");
        goto out;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct path p;
    p.mnt    = state->rename.mnt;
    p.dentry = old_dentry;
    ebpf_resolve_path_to_string(ss->rename.old_path, &p, task);
    p.dentry = new_dentry;
    ebpf_resolve_path_to_string(ss->rename.new_path, &p, task);

    state->rename.step = RENAME_STATE_PATHS_SET;

out:
    return 0;
}

SEC("fexit/vfs_rename")
int BPF_PROG(fexit__vfs_rename)
{
    int ret = FUNC_RET_READ(___type(ret), vfs_rename);
    if (ret)
        goto out;

    struct ebpf_fileevents_state *state = NULL;
    state                               = ebpf_fileevents_state__get(EBPF_FILEEVENTS_STATE_RENAME);
    if (!state || state->rename.step != RENAME_STATE_PATHS_SET) {
        bpf_printk("fexit__vfs_rename: state missing or incomplete\n");
        goto out;
    }

    struct ebpf_fileevents_scratch_space *ss =
        ebpf_fileevents_scratch_space__get(EBPF_FILEEVENTS_STATE_RENAME);
    if (!ss) {
        bpf_printk("fexit__vfs_rename: scratch space missing\n");
        goto out;
    }

    struct ebpf_file_rename_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->hdr.type = EBPF_EVENT_FILE_RENAME;
    event->hdr.ts   = bpf_ktime_get_ns();
    ebpf_pid_info__fill(&event->pids, task);
    bpf_probe_read_kernel_str(event->old_path, PATH_MAX_BUF, ss->rename.old_path);
    bpf_probe_read_kernel_str(event->new_path, PATH_MAX_BUF, ss->rename.new_path);

    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}
