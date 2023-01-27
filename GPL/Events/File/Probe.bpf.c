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
#include "State.h"
#include "Varlen.h"

/* vfs_unlink */
DECL_FUNC_ARG(vfs_unlink, dentry);
DECL_FUNC_RET(vfs_unlink);
/* vfs_rename */
DECL_FUNC_ARG(vfs_rename, old_dentry);
DECL_FUNC_ARG(vfs_rename, new_dentry);
DECL_FUNC_RET(vfs_rename);
DECL_FUNC_ARG_EXISTS(vfs_rename, rd);

static int mntns(const struct task_struct *task)
{
    return BPF_CORE_READ(task, nsproxy, mnt_ns, ns.inum);
}

static int do_unlinkat__enter()
{
    struct ebpf_events_state state = {};
    state.unlink.step              = UNLINK_STATE_INIT;
    if (ebpf_events_is_trusted_pid(0)) {
        return 0;
    }
    ebpf_events_state__set(EBPF_EVENTS_STATE_UNLINK, &state);
    return 0;
}

SEC("fentry/do_unlinkat")
int BPF_PROG(fentry__do_unlinkat)
{
    return do_unlinkat__enter();
}

SEC("kprobe/do_unlinkat")
int BPF_KPROBE(kprobe__do_unlinkat)
{
    return do_unlinkat__enter();
}

static int mnt_want_write__enter(struct vfsmount *mnt)
{
    struct ebpf_events_state *state = NULL;

    if (ebpf_events_is_trusted_pid(0)) {
        goto out;
    }
    state = ebpf_events_state__get(EBPF_EVENTS_STATE_UNLINK);
    if (state) {
        // Certain filesystems (eg. overlayfs) call mnt_want_write
        // multiple times during the same execution context.
        // Only take into account the first invocation.
        if (state->unlink.step != UNLINK_STATE_INIT)
            goto out;
        state->unlink.mnt  = mnt;
        state->unlink.step = UNLINK_STATE_MOUNT_SET;
        goto out;
    }

    state = ebpf_events_state__get(EBPF_EVENTS_STATE_RENAME);
    if (state) {
        // Certain filesystems (eg. overlayfs) call mnt_want_write
        // multiple times during the same execution context.
        // Only take into account the first invocation.
        if (state->rename.step != RENAME_STATE_INIT)
            goto out;
        state->rename.mnt  = mnt;
        state->rename.step = RENAME_STATE_MOUNT_SET;
        goto out;
    }

out:
    return 0;
}

SEC("fentry/mnt_want_write")
int BPF_PROG(fentry__mnt_want_write, struct vfsmount *mnt)
{
    return mnt_want_write__enter(mnt);
}

SEC("kprobe/mnt_want_write")
int BPF_KPROBE(kprobe__mnt_want_write, struct vfsmount *mnt)
{
    return mnt_want_write__enter(mnt);
}

static int vfs_unlink__exit(int ret)
{
    if (ret != 0)
        goto out;
    if (ebpf_events_is_trusted_pid(0))
        goto out;

    struct ebpf_events_state *state = ebpf_events_state__get(EBPF_EVENTS_STATE_UNLINK);
    if (!state || state->rename.step != UNLINK_STATE_DENTRY_SET) {
        // Omit logging as this happens in the happy path.
        goto out;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    struct ebpf_file_delete_event *event = get_event_buffer();
    if (!event) {
        bpf_printk("vfs_unlink__exit: failed to reserve event\n");
        goto out;
    }

    event->hdr.type = EBPF_EVENT_FILE_DELETE;
    event->hdr.ts   = bpf_ktime_get_ns();
    ebpf_pid_info__fill(&event->pids, task);

    struct path p;
    p.dentry     = &state->unlink.de;
    p.mnt        = state->unlink.mnt;
    event->mntns = mntns(task);
    bpf_get_current_comm(event->comm, TASK_COMM_LEN);

    // Variable length fields
    ebpf_vl_fields__init(&event->vl_fields);
    struct ebpf_varlen_field *field;
    long size;

    // path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_PATH);
    size  = ebpf_resolve_path_to_string(field->data, &p, task);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    bpf_ringbuf_output(&ringbuf, event, EVENT_SIZE(event), 0);

    // Certain filesystems (eg. overlayfs) call vfs_unlink twice during the same
    // execution context.
    // In order to not emit a second event, delete the state explicitly.
    ebpf_events_state__del(EBPF_EVENTS_STATE_UNLINK);

out:
    return 0;
}

SEC("fexit/vfs_unlink")
int BPF_PROG(fexit__vfs_unlink)
{
    int ret = FUNC_RET_READ(___type(ret), vfs_unlink);
    return vfs_unlink__exit(ret);
}

SEC("kretprobe/vfs_unlink")
int BPF_KRETPROBE(kretprobe__vfs_unlink, int ret)
{
    return vfs_unlink__exit(ret);
}

static int vfs_unlink__enter(struct dentry de)
{
    if (ebpf_events_is_trusted_pid(0))
        goto out;

    struct ebpf_events_state *state = ebpf_events_state__get(EBPF_EVENTS_STATE_UNLINK);
    if (!state || state->unlink.step != UNLINK_STATE_MOUNT_SET) {
        // Omit logging as this happens in the happy path.
        goto out;
    }

    state->unlink.de   = de;
    state->unlink.step = UNLINK_STATE_DENTRY_SET;

out:
    return 0;
}

SEC("fentry/vfs_unlink")
int BPF_PROG(fentry__vfs_unlink)
{
    struct dentry *tmp = FUNC_ARG_READ(___type(tmp), vfs_unlink, dentry);
    struct dentry de;
    bpf_core_read(&de, sizeof(de), tmp);
    return vfs_unlink__enter(de);
}

SEC("kprobe/vfs_unlink")
int BPF_KPROBE(kprobe__vfs_unlink)
{
    struct dentry de;
    int err = FUNC_ARG_READ_PTREGS(de, vfs_unlink, dentry);
    if (err) {
        bpf_printk("kprobe__vfs_unlink: error reading dentry\n");
        return 0;
    }

    return vfs_unlink__enter(de);
}

static int do_filp_open__exit(struct file *f)
{
    /*
    'ret' fields such f_mode and f_path should be obtained via BPF_CORE_READ
    because there's a kernel bug that causes a panic.
    Read more: github.com/torvalds/linux/commit/588a25e92458c6efeb7a261d5ca5726f5de89184
    */

    if (IS_ERR_OR_NULL(f))
        goto out;

    if (ebpf_events_is_trusted_pid(0))
        goto out;

    fmode_t fmode = BPF_CORE_READ(f, f_mode);
    if (fmode & (fmode_t)0x100000) { // FMODE_CREATED
        struct ebpf_file_create_event *event = get_event_buffer();
        if (!event)
            goto out;

        event->hdr.type = EBPF_EVENT_FILE_CREATE;
        event->hdr.ts   = bpf_ktime_get_ns();

        struct task_struct *task = (struct task_struct *)bpf_get_current_task();
        struct path p            = BPF_CORE_READ(f, f_path);
        ebpf_pid_info__fill(&event->pids, task);
        event->mntns = mntns(task);
        bpf_get_current_comm(event->comm, TASK_COMM_LEN);

        // Variable length fields
        ebpf_vl_fields__init(&event->vl_fields);
        struct ebpf_varlen_field *field;
        long size;

        // path
        field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_PATH);
        size  = ebpf_resolve_path_to_string(field->data, &p, task);
        ebpf_vl_field__set_size(&event->vl_fields, field, size);

        bpf_ringbuf_output(&ringbuf, event, EVENT_SIZE(event), 0);
    }

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
    return do_filp_open__exit(ret);
}

SEC("kretprobe/do_filp_open")
int BPF_KRETPROBE(kretprobe__do_filp_open, struct file *ret)
{
    return do_filp_open__exit(ret);
}

static int do_renameat2__enter()
{
    struct ebpf_events_state state = {};
    state.rename.step              = RENAME_STATE_INIT;

    if (ebpf_events_is_trusted_pid(0))
        goto out;
    ebpf_events_state__set(EBPF_EVENTS_STATE_RENAME, &state);

    u32 zero = 0;
    struct ebpf_events_scratch_space *ss =
        bpf_map_lookup_elem(&elastic_ebpf_events_init_buffer, &zero);
    if (!ss)
        goto out;
    ebpf_events_scratch_space__set(EBPF_EVENTS_STATE_RENAME, ss);

out:
    return 0;
}

SEC("fentry/do_renameat2")
int BPF_PROG(fentry__do_renameat2)
{
    return do_renameat2__enter();
}

SEC("kprobe/do_renameat2")
int BPF_KPROBE(kprobe__do_renameat2)
{
    return do_renameat2__enter();
}

static int vfs_rename__enter(struct dentry *old_dentry, struct dentry *new_dentry)
{
    struct ebpf_events_state *state;

    if (ebpf_events_is_trusted_pid(0))
        goto out;
    state = ebpf_events_state__get(EBPF_EVENTS_STATE_RENAME);
    if (!state || state->rename.step != RENAME_STATE_MOUNT_SET) {
        // Omit logging as this happens in the happy path.
        goto out;
    }

    struct ebpf_events_scratch_space *ss = ebpf_events_scratch_space__get(EBPF_EVENTS_STATE_RENAME);
    if (!ss) {
        bpf_printk("vfs_rename__enter: scratch space missing\n");
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

SEC("fentry/vfs_rename")
int BPF_PROG(fentry__vfs_rename)
{
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

    return vfs_rename__enter(old_dentry, new_dentry);
}

SEC("kprobe/vfs_rename")
int BPF_KPROBE(kprobe__vfs_rename)
{
    int err;
    struct dentry *old_dentry, *new_dentry;

    if (FUNC_ARG_EXISTS(vfs_rename, rd)) {
        /* Function arguments have been refactored into struct renamedata */
        struct renamedata rd;
        bpf_core_read(&rd, sizeof(rd), (void *)PT_REGS_PARM1(ctx));
        old_dentry = rd.old_dentry;
        new_dentry = rd.new_dentry;
    } else {
        /* Dentries are accessible from ctx */
        err = FUNC_ARG_READ_PTREGS_NODEREF(old_dentry, vfs_rename, old_dentry);
        if (err) {
            bpf_printk("kprobe__vfs_rename: error reading old_dentry\n");
            return 0;
        }
        err = FUNC_ARG_READ_PTREGS_NODEREF(new_dentry, vfs_rename, new_dentry);
        if (err) {
            bpf_printk("kprobe__vfs_rename: error reading new_dentry\n");
            return 0;
        }
    }

    return vfs_rename__enter(old_dentry, new_dentry);
}

static int vfs_rename__exit(int ret)
{
    if (ret)
        goto out;
    if (ebpf_events_is_trusted_pid(0))
        goto out;

    struct ebpf_events_state *state = ebpf_events_state__get(EBPF_EVENTS_STATE_RENAME);
    if (!state || state->rename.step != RENAME_STATE_PATHS_SET) {
        // Omit logging as this happens in the happy path.
        goto out;
    }

    struct ebpf_events_scratch_space *ss = ebpf_events_scratch_space__get(EBPF_EVENTS_STATE_RENAME);
    if (!ss) {
        bpf_printk("vfs_rename__exit: scratch space missing\n");
        goto out;
    }

    struct ebpf_file_rename_event *event = get_event_buffer();
    if (!event)
        goto out;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();

    event->hdr.type = EBPF_EVENT_FILE_RENAME;
    event->hdr.ts   = bpf_ktime_get_ns();
    ebpf_pid_info__fill(&event->pids, task);
    event->mntns = mntns(task);
    bpf_get_current_comm(event->comm, TASK_COMM_LEN);

    // Variable length fields
    ebpf_vl_fields__init(&event->vl_fields);
    struct ebpf_varlen_field *field;
    long size;

    // old path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_OLD_PATH);
    size  = read_kernel_str_or_empty_str(field->data, PATH_MAX, ss->rename.old_path);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    // new path
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_NEW_PATH);
    size  = read_kernel_str_or_empty_str(field->data, PATH_MAX, ss->rename.new_path);
    ebpf_vl_field__set_size(&event->vl_fields, field, size);

    bpf_ringbuf_output(&ringbuf, event, EVENT_SIZE(event), 0);

    // Certain filesystems (eg. overlayfs) call vfs_rename twice during the same
    // execution context.
    // In order to not emit a second event, delete the state explicitly.
    ebpf_events_state__del(EBPF_EVENTS_STATE_RENAME);

out:
    return 0;
}

SEC("fexit/vfs_rename")
int BPF_PROG(fexit__vfs_rename)
{
    int ret = FUNC_RET_READ(___type(ret), vfs_rename);
    return vfs_rename__exit(ret);
}

SEC("kretprobe/vfs_rename")
int BPF_KRETPROBE(kretprobe__vfs_rename, int ret)
{
    return vfs_rename__exit(ret);
}
