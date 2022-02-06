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
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "Helpers.h"
#include "Network.h"

static void __emit_network_event(enum ebpf_event_type typ, struct sock *sk)
{
    struct ebpf_net_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    if (ebpf_sock_info__fill(&event->net, sk)) {
        bpf_ringbuf_discard(event, 0);
        goto out;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ebpf_pid_info__fill(&event->pids, task);
    event->hdr.ts   = bpf_ktime_get_ns();
    event->hdr.type = typ;

    bpf_ringbuf_submit(event, 0);

out:
    return;
}

SEC("fexit/inet_csk_accept")
int BPF_PROG(
    fexit__inet_csk_accept, struct sock *sk, int flags, int *err, bool kern, struct sock *ret)
{
    if (!ret)
        goto out;

    __emit_network_event(EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED, ret);
out:
    return 0;
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(fexit__tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    if (ret)
        goto out;

    __emit_network_event(EBPF_EVENT_NETWORK_CONNECTION_ATTEMPTED, sk);
out:
    return 0;
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(fexit__tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    if (ret)
        goto out;

    __emit_network_event(EBPF_EVENT_NETWORK_CONNECTION_ATTEMPTED, sk);
out:
    return 0;
}
