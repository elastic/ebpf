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

    event->hdr.type = EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED;
    bpf_ringbuf_submit(event, 0);

out:
    return 0;
}

static int udp_skb_handle(struct sk_buff *skb, enum ebpf_net_udp_info evt_type)
{

    if (ebpf_events_is_trusted_pid())
        goto out;

    struct ebpf_dns_event *event = get_event_buffer();
    if (event == NULL)
        goto out;

    // read from skbuf
    unsigned char *skb_head = BPF_CORE_READ(skb, head);
    // get lengths
    u16 net_header_offset       = BPF_CORE_READ(skb, network_header);
    u16 transport_header_offset = BPF_CORE_READ(skb, transport_header);

    u8 proto = 0;

    struct iphdr ip_hdr;
    bpf_core_read(&ip_hdr, sizeof(struct iphdr), skb_head + net_header_offset);
    if (ip_hdr.version == 4) {
        proto = ip_hdr.protocol;

        bpf_probe_read(event->net.saddr, 4, &ip_hdr.saddr);
        bpf_probe_read(event->net.daddr, 4, &ip_hdr.daddr);

        event->net.family = EBPF_NETWORK_EVENT_AF_INET;
    } else if (ip_hdr.version == 6) {
        struct ipv6hdr ip6_hdr;
        bpf_core_read(&ip6_hdr, sizeof(struct ipv6hdr), skb_head + net_header_offset);
        proto = ip6_hdr.nexthdr;

        bpf_probe_read(event->net.saddr6, 16, ip6_hdr.saddr.in6_u.u6_addr8);
        bpf_probe_read(event->net.daddr6, 16, ip6_hdr.daddr.in6_u.u6_addr8);

        event->net.family = EBPF_NETWORK_EVENT_AF_INET6;
    }

    if (proto != IPPROTO_UDP) {
        goto out;
    }

    struct udphdr udp_hdr;
    bpf_core_read(&udp_hdr, sizeof(struct udphdr), skb_head + transport_header_offset);
    event->net.dport     = bpf_ntohs(udp_hdr.dest);
    event->net.sport     = bpf_ntohs(udp_hdr.source);
    event->net.transport = EBPF_NETWORK_EVENT_TRANSPORT_UDP;

    // filter out non-dns packets
    if (event->net.sport != 53 && event->net.dport != 53) {
        goto out;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ebpf_pid_info__fill(&event->pids, task);
    bpf_get_current_comm(event->comm, TASK_COMM_LEN);
    event->hdr.ts = bpf_ktime_get_ns();

    // constrain the read size to make the verifier happy
    // see skb_headlen() in skbuff.h
    size_t readsize = BPF_CORE_READ(skb, len);
    size_t datalen  = BPF_CORE_READ(skb, data_len);
    size_t headlen  = readsize - datalen;
    // headlen of zero indicates we have no non-paged data, and thus cannot read
    // anything from the root data node
    if (headlen == 0) {
        u32 zero                    = 0;
        struct ebpf_event_stats *es = bpf_map_lookup_elem(&ringbuf_stats, &zero);
        if (es != NULL) {
            es->lost++;
        }
        goto out;
    }

    if (headlen > MAX_DNS_PACKET) {
        headlen = MAX_DNS_PACKET;
    }

    ebpf_vl_fields__init(&event->vl_fields);
    struct ebpf_varlen_field *field;
    field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_DNS_BODY);

    long ret = bpf_probe_read_kernel(field->data, headlen,
                                     skb_head + transport_header_offset + sizeof(struct udphdr));
    if (ret != 0) {
        bpf_printk("error reading in data buffer: %d", ret);
        goto out;
    }
    ebpf_vl_field__set_size(&event->vl_fields, field, headlen);

    event->hdr.type = EBPF_EVENT_NETWORK_DNS_PKT;
    event->udp_evt  = evt_type;
    ebpf_ringbuf_write(&ringbuf, event, EVENT_SIZE(event), 0);

out:
    return 0;
}

SEC("fentry/ip_send_skb")
int BPF_PROG(fentry__ip_send_skb, struct net *net, struct sk_buff *skb)
{
    return udp_skb_handle(skb, EBPF_NETWORK_EVENT_IP_SEND_UDP);
}

SEC("fentry/skb_consume_udp")
int BPF_PROG(fentry__skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len)
{
    // skip peek operations
    if (len < 0) {
        return 0;
    }
    return udp_skb_handle(skb, EBPF_NETWORK_EVENT_SKB_CONSUME_UDP);
}

SEC("kprobe/ip_send_skb")
int BPF_KPROBE(kprobe__ip_send_udp, struct net *net, struct sk_buff *skb)
{
    return udp_skb_handle(skb, EBPF_NETWORK_EVENT_IP_SEND_UDP);
}

SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(kprobe__skb_consume_udp, struct net *net, struct sk_buff *skb, int len)
{
    // skip peek operations
    if (len < 0) {
        return 0;
    }
    return udp_skb_handle(skb, EBPF_NETWORK_EVENT_SKB_CONSUME_UDP);
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
