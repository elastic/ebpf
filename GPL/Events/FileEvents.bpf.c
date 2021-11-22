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
#include "libebpf.h"
#include "FileEvents.h"
#include "Maps.h"
#include "Helpers.h"

char LICENSE[] SEC("license") = "GPL";

// todo(fntlnz): this does not support unlink with a file descriptor.
// we probably want to switch to a security fexit and traverse the dentry
SEC("fexit/do_unlinkat")
int BPF_PROG(do_unlinkat_exit, int dfd, struct filename *name, long ret)
{
    if (ret != 0)
        goto out;

    struct ebpf_event *event = ebpf_event__new(&elastic_ebpf_events_buffer, EBPF_EVENT_FILE_DELETE);
    if (!event)
    {
        // todo(fntlnz): fentry cannot return anything but zero, handle error here
        goto out;
    }

    struct ebpf_event_file_delete_data *edata = (struct ebpf_event_file_delete_data *)event->data;
    ebpf_event_file_delete_data__set_pid(edata, bpf_get_current_pid_tgid() >> 32);
    ebpf_event_file_delete_data__set_dfd(edata, dfd);
    ebpf_event_file_delete_data__set_name(edata, name);
    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}
