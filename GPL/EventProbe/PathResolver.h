// SPDX-License-Identifier: GPL-2.0-only

/*
 * BPF dentry resolver
 *
 * This file contains code needed to construct a path as a string from Linux's
 * struct path object.
 *
 * Constructing paths in a BPF probe is complicated due to the fact that paths
 * are stored as the leaf of a struct dentry chain, with each dentry
 * corresponding to one path component. This means, to construct the full path
 * in string form, we have to walk the chain. Doign so completely for any
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

// Map used as a scratch area by the path resolver to store intermediate state
// (dentry pointers). Indexed by CPU number.
struct bpf_map_def SEC("maps") path_resolver_scratch_map = {
    .type        = BPF_MAP_TYPE_ARRAY,
    .max_entries = 128,
    .key_size    = sizeof(uint32_t),
    .value_size  = sizeof(struct dentry *) * PATH_RESOLVER_MAX_COMPONENTS,
};

static void
ebpf_resolve_path_to_string(char *buf, struct path *path, const struct task_struct *task)
{
    long size      = 0;
    bool truncated = true;

    // This function uses BPF_CORE_READ instead of raw kernel memory accesses
    // throughout. This is due to the pointer arithmentic below with
    // container_of (see note about struct mount below). BTF type information
    // is lost when we use container_of to access the struct mount, so we can't
    // use raw kernel memory dereferences.
    //
    // While we still have BTF information for task and other structs in this
    // function, BPF_CORE_READ is used for all of them too for uniformity and
    // simplicity.
    struct fs_struct *fs_struct    = BPF_CORE_READ(task, fs);
    struct path root               = BPF_CORE_READ(fs_struct, root);
    struct vfsmount *curr_vfsmount = BPF_CORE_READ(path, mnt);

    // All struct vfsmount's are stored in a struct mount. We need fields in
    // the struct mount to continue the dentry walk when we hit the root of a
    // mounted filesystem.
    struct mount *mnt          = container_of(curr_vfsmount, struct mount, mnt);
    struct dentry *curr_dentry = BPF_CORE_READ(path, dentry);
    struct dentry **dentry_arr;

    unsigned long cpu = bpf_get_smp_processor_id();
    if (!(dentry_arr = bpf_map_lookup_elem(&path_resolver_scratch_map, &cpu))) {
        ebpf_debug("Could not get path resolver scratch area for cpu %d", cpu);
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
            ebpf_debug("path under construction is too long: %s", buf);
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
            ebpf_debug("could not read d_name at %p, current path %s", component.name, buf);
            goto out_err;
        }
    }

    // Special case: root directory. If the path is "/", the above loop will
    // not have run and thus path_string will be an empty string. We handle
    // that case here.
    if (buf[0] == '\0') {
        buf[0] = '/';
        buf[1] = '\0';
    }

    return;

out_err:
    buf[0] = '\0';
}

#endif // EBPF_EVENTPROBE_PATHRESOLVER_H
