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

#ifndef EBPF_EVENTPROBE_FILEEVENTS_H
#define EBPF_EVENTPROBE_FILEEVENTS_H

#include "EbpfEventProto.h"

typedef struct dentry* dentries[MAX_PATH_DEPTH];

static __always_inline int ebpf_event_file__dentry_walk(dentries des, struct vfsmount *vfsmnt, struct dentry* src)
{
    struct dentry *parent_dentry = NULL;
    struct dentry *current_dentry = NULL;
    struct vfsmount *current_vfsmount = vfsmnt;
    struct mount *mnt = NULL;
    struct mount *parent_mnt = NULL;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct fs_struct *filesystem = BPF_CORE_READ(task, fs);
    struct path root_path = BPF_CORE_READ(filesystem, root);

    size_t des_len = 0;

    des[0] = src;

    for (int i = 0; i < MAX_PATH_DEPTH; i++)
    {
        if(root_path.dentry == current_dentry)
        {
            break;
        }
        if (i == 0)
        {
            parent_dentry = BPF_CORE_READ(src, d_parent);
            current_dentry = parent_dentry;
        }
        else
        {
            current_dentry = BPF_CORE_READ(parent_dentry, d_parent); 
            if(current_dentry == parent_dentry || current_dentry == BPF_CORE_READ(current_vfsmount, mnt_root))
            {
                mnt = container_of(current_vfsmount, struct mount, mnt);
                current_dentry = BPF_CORE_READ(mnt, mnt_mountpoint);
                parent_mnt = BPF_CORE_READ(mnt, mnt_parent);
                if (parent_mnt == mnt)
                {
                    break;
                }
                mnt = parent_mnt;
                current_vfsmount = &mnt->mnt;
            }
            parent_dentry = current_dentry;
        }

        if (i + 1 < MAX_PATH_DEPTH)
        {
            des[i + 1] = current_dentry;
        }
        des_len += 1;
    }
    return des_len;
}

static __always_inline int ebpf_event_file_path__from_dentry(struct ebpf_file_path *dst, struct vfsmount *mnt, struct dentry* src)
{
    dentries des = {};
    int des_len = ebpf_event_file__dentry_walk(des, mnt, src);

    int j = 0;
    for (int i = des_len; i != 0; i--)
    {
        bpf_probe_read_kernel_str(dst->path_array[j], MAX_PATH, BPF_CORE_READ(des[i - 1], d_name.name));
        j = j + 1;
    }

    dst->patharray_len = j;
    return j;
}

#endif // EBPF_EVENTS_FILEEVENTS_H
