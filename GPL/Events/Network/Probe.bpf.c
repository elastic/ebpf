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

DECL_FUNC_RET(inet_csk_accept);

static int sock_object_handle(struct sock *sk, enum ebpf_event_type evt_type)
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

    event->hdr.type = evt_type;
    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}

static int
handle_consume(struct sock *sk, struct sk_buff *skb, int len, enum ebpf_event_type evt_type)
{
    if (!sk) {
        return 0;
    }

    if (ebpf_events_is_trusted_pid())
        return 0;

    struct ebpf_dns_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        return 0;

    // fill in socket and process metadata
    if (ebpf_sock_info__fill(&event->net, sk)) {
        goto out;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ebpf_pid_info__fill(&event->pids, task);
    bpf_get_current_comm(event->comm, TASK_COMM_LEN);
    event->hdr.ts = bpf_ktime_get_ns();

    // filter out non-dns packets
    if (event->net.dport != 53 && event->net.sport != 53) {
        bpf_printk("not a dns packet...");
        goto out;
    }

    // constrain the read size to make the verifier happy
    long readsize = BPF_CORE_READ(skb, len);
    if (readsize > MAX_DNS_PACKET) {
        readsize = MAX_DNS_PACKET;
    }

    // udp_send_skb includes the IP and UDP header, so offset
    long offset = 0;
    if (evt_type == EBPF_EVENT_NETWORK_SEND_SKB) {
        offset = 28;
    }

    unsigned char *data = BPF_CORE_READ(skb, data);
    long ret            = bpf_probe_read_kernel(event->pkt, readsize, data + offset);
    if (ret != 0) {
        bpf_printk("error reading in data buffer: %d", ret);
        goto out;
    }

    event->hdr.type = EBPF_EVENT_NETWORK_DNS_PKT;
    event->udp_evt  = evt_type;
    bpf_ringbuf_submit(event, 0);

    return 0;

out:
    bpf_ringbuf_discard(event, 0);
    return 0;
}

/*
=============================== DNS probes ===============================
*/

// SEC("fentry/udp_sendmsg")
// int BPF_PROG(fentry__udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
// {
//     return sock_dns_event_handle(sk, msg, EBPF_EVENT_NETWORK_UDP_SENDMSG, size);
// }

SEC("fentry/udp_send_skb")
int BPF_PROG(fentry__udp_send_skb, struct sk_buff *skb, struct flowi4 *fl4, struct inet_cork *cork)
{
    return handle_consume(skb->sk, skb, skb->len, EBPF_EVENT_NETWORK_SEND_SKB);
}

SEC("fentry/skb_consume_udp")
int BPF_PROG(fentry__skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len)
{
    // a negative size indicates peeking, ignore
    if (len <= 0) {
        return 0;
    }
    return handle_consume(sk, skb, len, EBPF_EVENT_NETWORK_CONSUME_SKB);
}

SEC("kprobe/udp_send_skb")
int BPF_KPROBE(kprobe__udp_send_skb,
               struct sk_buff *skb,
               struct flowi4 *fl4,
               struct inet_cork *cork)
{
    struct sock *sk  = BPF_CORE_READ(skb, sk);
    unsigned int len = BPF_CORE_READ(skb, len);
    return handle_consume(sk, skb, len, EBPF_EVENT_NETWORK_SEND_SKB);
}

SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(kprobe__skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len)
{
    // a negative size indicates peeking, ignore
    if (len <= 0) {
        return 0;
    }
    return handle_consume(sk, skb, len, EBPF_EVENT_NETWORK_CONSUME_SKB);
}

/*
=============================== TCP probes ===============================
*/

SEC("fexit/inet_csk_accept")
int BPF_PROG(fexit__inet_csk_accept)
{
    struct sock *ret = FUNC_RET_READ(___type(ret), inet_csk_accept);
    return sock_object_handle(ret, EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED);
}

SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(kretprobe__inet_csk_accept, struct sock *ret)
{
    return sock_object_handle(ret, EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED);
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
