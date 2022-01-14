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

#if BPF_DEBUG_TRACE == 0
#undef bpf_printk
#define bpf_printk(fmt, ...)
#endif

#define DECL_RELO_FUNC_ARGUMENT(func_name, arg_name)                                               \
    const volatile int arg__##func_name##__##arg_name##__ = 0;
#define RELO_FENTRY_ARG_READ(type, func_name, arg_name)                                            \
    ({                                                                                             \
        type _ret;                                                                                 \
        bpf_core_read(&_ret, sizeof(_ret),                                           \
                      ctx + arg__##func_name##__##arg_name##__);                                   \
        _ret;                                                                                      \
    })

#define DECL_RELO_FUNC_RET(func_name) const volatile int ret__##func_name##__ = 0;
#define RELO_FENTRY_RET_READ(type, func_name)                                                      \
    ({                                                                                             \
        type _ret;                                                                                 \
        bpf_core_read(&_ret, sizeof(_ret), ctx + ret__##func_name##__);              \
        _ret;                                                                                      \
    })

// From linux/err.h
#define MAX_ERRNO 4095

static bool IS_ERR_OR_NULL(const void *ptr)
{
    return (!ptr) || (unsigned long)ptr >= (unsigned long)-MAX_ERRNO;
}

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
    pi->tid  = BPF_CORE_READ(task, pid);
    pi->tgid = BPF_CORE_READ(task, tgid);
    pi->ppid = BPF_CORE_READ(task, group_leader, real_parent, tgid);
    pi->pgid = BPF_CORE_READ(task, group_leader, signal, pids[PIDTYPE_PGID], numbers[0].nr);
    pi->sid  = BPF_CORE_READ(task, group_leader, signal, pids[PIDTYPE_SID], numbers[0].nr);
    pi->start_time_ns = BPF_CORE_READ(task, group_leader, start_time);
}

static void ebpf_cred_info__fill(struct ebpf_cred_info *ci, const struct task_struct *task)
{
    ci->ruid = task->cred->uid.val;
    ci->euid = task->cred->euid.val;
    ci->suid = task->cred->suid.val;
    ci->rgid = task->cred->gid.val;
    ci->egid = task->cred->egid.val;
    ci->sgid = task->cred->sgid.val;
}

static bool is_kernel_thread(const struct task_struct *task)
{
    // Session ID is 0 for all kernel threads
    return task->group_leader->signal->pids[PIDTYPE_SID]->numbers[0].nr == 0;
}

#endif // EBPF_EVENTPROBE_HELPERS_H
