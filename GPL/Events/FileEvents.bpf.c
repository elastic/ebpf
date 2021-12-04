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
#include "libebpf.h"
#include "FileEvents.h"
#include "Maps.h"
#include "Helpers.h"

char LICENSE[] SEC("license") = "GPL";


SEC("fexit/security_path_unlink")
int BPF_PROG(security_path_unlink_exit, const struct path *dir, struct dentry *dentry, long ret)
{
    struct ebpf_event *event = NULL;
    struct ebpf_event_file_delete_data *edata = NULL;
    struct task_struct *task = NULL;

    if (ret != 0)
        goto out;


    event = ebpf_event__new(&elastic_ebpf_events_buffer, EBPF_EVENT_FILE_DELETE);
    if (!event)
    {
        // todo(fntlnz): fentry cannot return anything but zero, handle error here
        goto out;
    }

    
    edata = (struct ebpf_event_file_delete_data *)event->data;
    ebpf_event_file_delete_data__set_pid(edata, bpf_get_current_pid_tgid() >> 32);

    size_t len = ebpf_event_file_path__from_dentry(&edata->path, dentry);

    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}
