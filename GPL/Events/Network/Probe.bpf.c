// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#include "vmlinux.h"

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#include "Helpers.h"
#include "Network.h"
#include "State.h"
#include "Varlen.h"

DECL_FUNC_RET(inet_csk_accept);

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 131072);
    __type(key, struct sock *);
    __type(value, u32);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} sk_to_tgid SEC(".maps");

static int inet_csk_accept__exit(struct sock *sk)
{
    if (!sk)
        goto out;
    if (ebpf_events_is_trusted_pid())
        goto out;

    struct ebpf_net_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    if (ebpf_network_event__fill(event, sk)) {
        bpf_ringbuf_discard(event, 0);
        goto out;
    }
    // Record this socket so we can emit a close
    u32 tgid = event->pids.tgid;
    (void)bpf_map_update_elem(&sk_to_tgid, &sk, &tgid, BPF_ANY);

    event->hdr.type = EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED;
    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}

SEC("fexit/inet_csk_accept")
int BPF_PROG(fexit__inet_csk_accept)
{
    struct sock *ret = FUNC_RET_READ(___type(ret), inet_csk_accept);
    return inet_csk_accept__exit(ret);
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe__inet_csk_accept, struct sock *ret)
{
    return inet_csk_accept__exit(ret);
}

static int tcp_connect(struct sock *sk, int ret)
{
    if (ret)
        goto out;
    if (ebpf_events_is_trusted_pid())
        goto out;

    struct ebpf_net_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    if (ebpf_network_event__fill(event, sk)) {
        bpf_ringbuf_discard(event, 0);
        goto out;
    }

    // Record this socket so we can emit a close
    u32 tgid = event->pids.tgid;
    (void)bpf_map_update_elem(&sk_to_tgid, &sk, &tgid, BPF_ANY);

    event->hdr.type = EBPF_EVENT_NETWORK_CONNECTION_ATTEMPTED;
    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}

SEC("fexit/tcp_v4_connect")
int BPF_PROG(fexit__tcp_v4_connect, struct sock *sk, struct sockaddr *uaddr, int addr_len, int ret)
{
    return tcp_connect(sk, ret);
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe__tcp_v4_connect, struct sock *sk)
{
    struct ebpf_events_state state = {};
    state.tcp_v4_connect.sk        = sk;
    if (ebpf_events_is_trusted_pid())
        return 0;
    ebpf_events_state__set(EBPF_EVENTS_STATE_TCP_V4_CONNECT, &state);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kretprobe__tcp_v4_connect, int ret)
{
    struct ebpf_events_state *state;

    state = ebpf_events_state__get(EBPF_EVENTS_STATE_TCP_V4_CONNECT);
    if (!state)
        return 0;

    return tcp_connect(state->tcp_v4_connect.sk, ret);
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
    if (ebpf_events_is_trusted_pid())
        return 0;
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

static int tcp_close__enter(struct sock *sk)
{
    if (ebpf_events_is_trusted_pid())
        goto out;

    struct tcp_sock *tp = (struct tcp_sock *)sk;
    u64 bytes_sent      = BPF_CORE_READ(tp, bytes_sent);
    u64 bytes_received  = BPF_CORE_READ(tp, bytes_received);

    // Only process sockets we added, but since storage is limited, fall back to
    // looking at bytes if we're full
    if (bpf_map_delete_elem(&sk_to_tgid, &sk) != 0 && bytes_sent == 0 && bytes_received == 0)
        goto out;

    struct ebpf_net_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        goto out;

    if (ebpf_network_event__fill(event, sk)) {
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

SEC("fentry/tcp_close")
int BPF_PROG(fentry__tcp_close, struct sock *sk, long timeout)
{
    return tcp_close__enter(sk);
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(kprobe__tcp_close, struct sock *sk, long timeout)
{
    return tcp_close__enter(sk);
}
