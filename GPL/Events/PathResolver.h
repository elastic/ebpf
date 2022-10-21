// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

/*
 * BPF dentry resolver
 *
 * This file contains code needed to construct a path as a string from Linux's
 * struct path object.
 *
 * Constructing paths in a BPF probe is complicated due to the fact that paths
 * are stored as the leaf of a struct dentry chain, with each dentry
 * corresponding to one path component. This means, to construct the full path
 * in string form, we have to walk the chain. Doing so completely for any
 * arbitrarily long path is impossible as that would require an unbounded loop,
 * so we make a best effort with a bounded loop, truncating particularly long
 * paths.
 */

#ifndef EBPF_EVENTPROBE_PATHRESOLVER_H
#define EBPF_EVENTPROBE_PATHRESOLVER_H

#include "vmlinux.h"

#include "Helpers.h"

#define PATH_MAX 4096
#define PATH_MAX_INDEX_MASK 4095

// Maximum number of path components we'll grab before we give up and just
// prepend "./" to the path. Even though bumping this won't increase the number
// of instructions in the resolver (loops are not unrolled), it will increase
// the number of states that need to be explored by the verifier, which, if
// high enough, will bump up against BPF_COMPLEXITY_LIMIT_INSNS in the kernel
// (set to 1,000,000 as of 5.3).
#define PATH_RESOLVER_MAX_COMPONENTS 100

#define KERNFS_NODE_COMPONENT_MAX_LEN 250

// Map used as a scratch area by the path resolver to store intermediate state
// (dentry pointers).
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct dentry *[PATH_RESOLVER_MAX_COMPONENTS]);
    __uint(max_entries, 1);
} path_resolver_dentry_scratch_map SEC(".maps");

// Resolve a struct path to a string. Returns the size of the constructed path
// string, including the null terminator.
static size_t
ebpf_resolve_path_to_string(char *buf, struct path *path, const struct task_struct *task)
{
    long size      = 0;
    bool truncated = true;

    struct fs_struct *fs_struct    = BPF_CORE_READ(task, fs);
    struct path root               = BPF_CORE_READ(fs_struct, root);
    struct vfsmount *curr_vfsmount = BPF_CORE_READ(path, mnt);

    // All struct vfsmount's are stored in a struct mount. We need fields in
    // the struct mount to continue the dentry walk when we hit the root of a
    // mounted filesystem.
    struct mount *mnt          = container_of(curr_vfsmount, struct mount, mnt);
    struct dentry *curr_dentry = BPF_CORE_READ(path, dentry);
    struct dentry **dentry_arr;

    // Ensure we make buf an empty string early up here so if we exit with any
    // sort of error, we won't leave garbage in it if it's uninitialized
    buf[0] = '\0';

    u32 zero = 0;
    if (!(dentry_arr = bpf_map_lookup_elem(&path_resolver_dentry_scratch_map, &zero))) {
        bpf_printk("Could not get path resolver scratch area");
        goto out_err;
    }

    // Loop 1, follow the dentry chain (up to a maximum of
    // PATH_RESOLVER_MAX_COMPONENTS) and store pointers to each dentry in
    // dentry_arr
    for (int i = 0; i < PATH_RESOLVER_MAX_COMPONENTS; i++) {
        if (curr_dentry == root.dentry && curr_vfsmount == root.mnt) {
            // We've reached the global root if both the current dentry and the
            // current vfsmount match those of the root struct path. Fill in
            // the rest of dentry_arr with NULLs so the next loop ignores the
            // remaining entries.
            truncated     = false;
            dentry_arr[i] = NULL;
            continue;
        }

        struct dentry *parent = BPF_CORE_READ(curr_dentry, d_parent);
        if (curr_dentry == parent || curr_dentry == BPF_CORE_READ(curr_vfsmount, mnt_root)) {

            // We've hit the root of a mounted filesystem. The dentry walk must
            // be continued from mnt_mountpoint in the current struct mount.
            // Also update curr_vfsmount to point to the parent filesystem root.
            curr_dentry   = (struct dentry *)BPF_CORE_READ(mnt, mnt_mountpoint);
            mnt           = BPF_CORE_READ(mnt, mnt_parent);
            curr_vfsmount = (struct vfsmount *)&mnt->mnt;

            // We might be at another fs root here (in which case
            // curr_dentry->d_name will have "/", we need to go up another
            // level to get an actual component name), so fill the dentry
            // pointer array at this spot with NULL so it's ignored in the next
            // loop and continue to check the above condition again.
            dentry_arr[i] = NULL;
            continue;
        }

        dentry_arr[i] = curr_dentry;
        curr_dentry   = parent;
    }

    if (truncated) {
        // Use a relative path eg. ./some/dir as a best effort if we have
        // more components than PATH_RESOLVER_MAX_COMPONENTS.
        buf[0] = '.';
        size   = 1;
    }

    // Loop 2, walk the array of dentry pointers (in reverse order) and
    // copy the d_name component of each one into buf, separating with '/'
    for (int i = PATH_RESOLVER_MAX_COMPONENTS - 1; i >= 0; i--) {
        struct dentry *dentry = dentry_arr[i];
        if (dentry == NULL)
            continue;

        struct qstr component = BPF_CORE_READ(dentry, d_name);
        if (size + component.len + 1 > PATH_MAX) {
            bpf_printk("path under construction is too long: %s", buf);
            goto out_err;
        }

        // Note that even though the value of size is guaranteed to be
        // less than PATH_MAX_INDEX_MASK here, we have to apply the bound again
        // before using it an index into an array as if it's spilled to the
        // stack by the compiler, the verifier bounds information will not be
        // retained after each bitwise and (this only carries over when stored
        // in a register).
        buf[size & PATH_MAX_INDEX_MASK] = '/';
        size                            = (size + 1) & PATH_MAX_INDEX_MASK;

        int ret = bpf_probe_read_kernel_str(buf + (size & PATH_MAX_INDEX_MASK),
                                            PATH_MAX > size ? PATH_MAX - size : 0,
                                            (void *)component.name);

        if (ret > 0) {
            size += ((ret - 1) & PATH_MAX_INDEX_MASK);
        } else {
            bpf_printk("could not read d_name at %p, current path %s", component.name, buf);
            goto out_err;
        }
    }

    // Special case: root directory. If the path is "/", the above loop will
    // not have run and thus path_string will be an empty string. We handle
    // that case here.
    if (buf[0] == '\0') {
        buf[0] = '/';
        buf[1] = '\0';
        size   = 1;
    }

    return size + 1; // size does not include the \0

out_err:
    buf[0] = '\0';
    return 1;
}

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __type(key, u32);
    __type(value, struct kernfs_node *[PATH_RESOLVER_MAX_COMPONENTS]);
    __uint(max_entries, 1);
} path_resolver_kernfs_node_scratch_map SEC(".maps");

// Resolve a struct kernfs_node to a string. Returns the size of the
// constructed path string, including the null terminator.
static size_t ebpf_resolve_kernfs_node_to_string(char *buf, struct kernfs_node *kn)
{
    size_t cur = 0;
    int depth = 0, zero = 0, read_len, name_len;
    char name[KERNFS_NODE_COMPONENT_MAX_LEN];
    buf[0] = '\0';

    struct kernfs_node **kna = bpf_map_lookup_elem(&path_resolver_kernfs_node_scratch_map, &zero);
    if (!kna) {
        bpf_printk("could not get scratch area");
        goto out_err;
    }

    while (depth < PATH_RESOLVER_MAX_COMPONENTS - 1) {
        if (!kn)
            break;

        kna[depth] = kn;
        kn         = BPF_CORE_READ(kn, parent);
        depth++;
    }

    while (depth > 0) {
        depth--;
        struct kernfs_node *curr = kna[depth];

        read_len = bpf_probe_read_kernel_str(&name, KERNFS_NODE_COMPONENT_MAX_LEN,
                                             (void *)BPF_CORE_READ(curr, name));
        if (read_len < 0) {
            bpf_printk("could not get read kernfs_node name: %d", read_len);
            goto out_err;
        }

        name_len = read_len - 1;
        if (name_len == 0)
            continue;

        if (cur + name_len + 1 > PATH_MAX) {
            bpf_printk("path too long");
            goto out_err;
        }

        buf[cur & PATH_MAX_INDEX_MASK] = '/';
        cur                            = (cur + 1) & PATH_MAX_INDEX_MASK;
        if (bpf_probe_read_kernel_str(
                buf + (cur & PATH_MAX_INDEX_MASK),
                PATH_MAX - cur > KERNFS_NODE_COMPONENT_MAX_LEN ? KERNFS_NODE_COMPONENT_MAX_LEN : 0,
                (void *)name) < 0)
            goto out_err;

        cur += name_len & PATH_MAX_INDEX_MASK;
    }

    return cur + 1; // cur does not include the \0

out_err:
    buf[0] = '\0';
    return 1;
}

static size_t ebpf_resolve_pids_ss_cgroup_path_to_string(char *buf, const struct task_struct *task)
{
    /*
     * Since pids_cgrp_id is an enum value, we need to get it at runtime as it
     * can change kernel-to-kernel depending on the kconfig or possibly not be
     * enabled at all.
     */
    int cgrp_id;
    if (bpf_core_enum_value_exists(enum cgroup_subsys_id, pids_cgrp_id)) {
        cgrp_id = bpf_core_enum_value(enum cgroup_subsys_id, pids_cgrp_id);
    } else {
        /* Pids cgroup is not enabled on this kernel */
        buf[0] = '\0';
        return 1;
    }

    struct kernfs_node *kn = BPF_CORE_READ(task, cgroups, subsys[cgrp_id], cgroup, kn);
    return ebpf_resolve_kernfs_node_to_string(buf, kn);
}

#endif // EBPF_EVENTPROBE_PATHRESOLVER_H
