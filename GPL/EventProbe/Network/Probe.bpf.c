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
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "Helpers.h"
#include "Network.h"
#include "State.h"

// TODO: aarch64
SEC("fexit/inet_csk_accept")
int BPF_PROG(
    fexit__inet_csk_accept, struct sock *sk, int flags, int *err, bool kern, struct sock *ret)
{
    if (!ret)
        goto out;

    struct ebpf_net_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    if (ebpf_network_event__fill(event, ret)) {
        bpf_ringbuf_discard(event, 0);
        goto out;
    }

    event->hdr.type = EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED;
    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}

static int tcp_connect(struct sock *sk, int ret)
{
    if (ret)
        goto out;

    struct ebpf_net_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    if (ebpf_network_event__fill(event, sk)) {
        bpf_ringbuf_discard(event, 0);
        goto out;
    }

    event->hdr.type = EBPF_EVENT_NETWORK_CONNECTION_ATTEMPTED;
    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}

// TODO: aarch64
SEC("fexit/tcp_v4_connect")
int BPF_PROG(fexit__tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    return tcp_connect(sk, ret);
}

SEC("fexit/tcp_v6_connect")
int BPF_PROG(fexit__tcp_v6_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    return tcp_connect(sk, ret);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kprobe__tcp_v6_connect, struct sock *sk)
{
    struct ebpf_events_state state = {};
    state.tcp_v6_connect.sk        = sk;
    ebpf_events_state__set(EBPF_EVENTS_STATE_TCP_V6_CONNECT, &state);
    return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(kretprobe__tcp_v6_connect, int ret)
{
    struct ebpf_events_state *state;

    state = ebpf_events_state__get(EBPF_EVENTS_STATE_TCP_V6_CONNECT);
    if (!state)
        return 0;

    return tcp_connect(state->tcp_v6_connect.sk, ret);
}

// TODO: aarch64
SEC("fentry/tcp_close")
int BPF_PROG(fentry__tcp_close, struct sock *sk, long timeout)
{
    struct ebpf_net_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    if (ebpf_network_event__fill(event, sk)) {
        bpf_ringbuf_discard(event, 0);
        goto out;
    }

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    u64 bytes_sent      = BPF_CORE_READ(tp, bytes_sent);
    u64 bytes_received  = BPF_CORE_READ(tp, bytes_received);

    if (!bytes_sent && !bytes_received) {
        // Uninteresting event, most likely unbound or unconnected socket.
        bpf_ringbuf_discard(event, 0);
        goto out;
    }

    event->net.tcp.close.bytes_sent     = bytes_sent;
    event->net.tcp.close.bytes_received = bytes_received;

    event->hdr.type = EBPF_EVENT_NETWORK_CONNECTION_CLOSED;
    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}
