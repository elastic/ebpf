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

#ifndef EBPF_EVENTPROBE_HELPERS_H
#define EBPF_EVENTPROBE_HELPERS_H

#include "EbpfEventProto.h"
#include "FileEvents.h"

static void ebpf_argv__fill(char *buf, size_t buf_size, const struct task_struct *task)
{
    unsigned long start, end, size;

    start = task->mm->arg_start;
    end   = task->mm->arg_end;

    size = end - start;
    size = size > buf_size ? buf_size : size;

    bpf_probe_read_user(buf, size, (void *)start);

    // Prevent final arg from being unterminated if buf is too small for args
    buf[buf_size - 1] = '\0';
}

static void ebpf_ctty__fill(struct ebpf_tty_dev *ctty, const struct task_struct *task)
{
    ctty->major = task->signal->tty->driver->major;
    ctty->minor = task->signal->tty->driver->minor_start;
    ctty->minor += task->signal->tty->index;
}

static void ebpf_pid_info__fill(struct ebpf_pid_info *pi, const struct task_struct *task)
{
    pi->tgid = task->tgid;
    pi->sid  = task->group_leader->signal->pids[PIDTYPE_SID]->numbers[0].nr;
}

static bool is_kernel_thread(const struct task_struct *task)
{
    // Session ID is 0 for all kernel threads
    return task->group_leader->signal->pids[PIDTYPE_SID]->numbers[0].nr == 0;
}

#endif // EBPF_EVENTPROBE_HELPERS_H
