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

static int udp_skb_handle(struct sk_buff *skb, enum ebpf_net_udp_info evt_type)
{
    if (skb == NULL) {
        goto out;
    }

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
    size_t network_header_size  = 0;
    u8 proto                    = 0;

    struct iphdr ip_hdr;
    bpf_core_read(&ip_hdr, sizeof(struct iphdr), skb_head + net_header_offset);
    if (ip_hdr.version == 4) {
        proto = ip_hdr.protocol;

        if (bpf_probe_read(event->net.saddr, 4, &ip_hdr.saddr) != 0) {
            goto out;
        };

        if (bpf_probe_read(event->net.daddr, 4, &ip_hdr.daddr) != 0) {
            goto out;
        }
        network_header_size = sizeof(struct iphdr);
        event->net.family   = EBPF_NETWORK_EVENT_AF_INET;
    } else if (ip_hdr.version == 6) {
        struct ipv6hdr ip6_hdr;
        bpf_core_read(&ip6_hdr, sizeof(struct ipv6hdr), skb_head + net_header_offset);
        proto = ip6_hdr.nexthdr;

        if (bpf_probe_read(event->net.saddr6, 16, ip6_hdr.saddr.in6_u.u6_addr8) != 0) {
            goto out;
        }

        if (bpf_probe_read(event->net.daddr6, 16, ip6_hdr.daddr.in6_u.u6_addr8) != 0) {
            goto out;
        }

        network_header_size = sizeof(struct ipv6hdr);
        event->net.family   = EBPF_NETWORK_EVENT_AF_INET6;
    } else {
        goto out;
    }

    if (proto != IPPROTO_UDP) {
        goto out;
    }

    struct udphdr udp_hdr;
    if (bpf_core_read(&udp_hdr, sizeof(struct udphdr), skb_head + transport_header_offset) != 0) {
        goto out;
    }

    uint16_t dport = bpf_ntohs(udp_hdr.dest);
    uint16_t sport = bpf_ntohs(udp_hdr.source);
    // filter out non-DNS packets
    if (sport != 53 && dport != 53) {
        goto out;
    }

    event->net.dport     = dport;
    event->net.sport     = sport;
    event->net.transport = EBPF_NETWORK_EVENT_TRANSPORT_UDP;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ebpf_pid_info__fill(&event->pids, task);
    bpf_get_current_comm(event->comm, TASK_COMM_LEN);
    event->hdr.ts      = bpf_ktime_get_ns();
    event->hdr.ts_boot = bpf_ktime_get_boot_ns_helper();

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
            es->dns_zero_body++;
        }
        goto out;
    }

    size_t body_size = headlen;
    // for ip_send_skb(), we're at a point in the network stack where we've just prepended the IP
    // header, so the normal headlen for the skb_buff includes the headers. Reset them so we *just*
    // read the application body.
    if (evt_type == EBPF_NETWORK_EVENT_IP_SEND_UDP) {
        body_size = headlen - (sizeof(struct udphdr) + network_header_size);
    }

    event->original_len = headlen;
    if (body_size > MAX_DNS_PACKET) {
        body_size = MAX_DNS_PACKET;
    }

    ebpf_vl_fields__init(&event->vl_fields);
    struct ebpf_varlen_field *field;
    field    = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_DNS_BODY);
    long ret = bpf_probe_read_kernel(field->data, body_size,
                                     skb_head + transport_header_offset + sizeof(struct udphdr));
    if (ret != 0) {
        bpf_printk("error reading in data buffer: %d", ret);
        goto out;
    }
    ebpf_vl_field__set_size(&event->vl_fields, field, body_size);

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

/* XXX naive, only handles ROUTING and DEST, untested */
int skb_peel_nexthdr(struct __sk_buff *skb, u8 wanted)
{
	struct ipv6hdr ip6;
	int off;
	u16 next;

	off = 0;
	if (bpf_skb_load_bytes(skb, off, &ip6, sizeof(ip6)))
		return (-1);
	off += sizeof(ip6);
	next = ip6.nexthdr;

	for (;;) {
		if (next == wanted)
			return (off);
		switch (next) {
		case NEXTHDR_ROUTING: /* FALLTHROUGH */
		case NEXTHDR_DEST:
			if (bpf_skb_load_bytes(skb, off, &next, sizeof(next)))
				return (-1);
			off += (next >> 8) + 1;
			next = next & 0xff;
		default:
			return (-1);
		}
	}
}

int skb_in_or_egress(struct __sk_buff *skb, int ingress)
{
	struct udphdr udp;
	struct bpf_sock *sk, *sk2;
	u32 *tgid, cap_len;
	struct ebpf_dns_event2 *event;
	struct ebpf_varlen_field *field;

	if (skb->family != AF_INET && skb->family != AF_INET6)
		goto ignore;
	if ((sk = skb->sk) == NULL)
		goto ignore;
	if ((sk = bpf_sk_fullsock(sk)) == NULL)
		goto ignore;
	if (sk->family != AF_INET && sk->family != AF_INET6)
		goto ignore;
	if (sk->protocol != IPPROTO_UDP)
		goto ignore;

	if (sk->family == AF_INET) {
		struct iphdr ip;

		if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip))) {
			bpf_printk("copy error 1");
			goto ignore;
		}
		if (bpf_skb_load_bytes(skb, ip.ihl << 2, &udp, sizeof(udp))) {
			bpf_printk("copy error 2");
			goto ignore;
		}
		if (ip.protocol != IPPROTO_UDP)
			goto ignore;
	} else if (sk->family == AF_INET6) {
		int t_off;

		t_off = skb_peel_nexthdr(skb, NEXTHDR_UDP);
		if (t_off == -1)
			goto ignore;

		if (bpf_skb_load_bytes(skb, t_off, &udp, sizeof(udp))) {
			bpf_printk("copy error 4");
			goto ignore;
		}
	}

	if (bpf_ntohs(udp.dest) != 53 && bpf_ntohs(udp.source) != 53)
		goto ignore;

	sk2 = sk;
	tgid = bpf_map_lookup_elem(&sk_to_tgid, &sk2);
	if (tgid == NULL) {
		bpf_printk("udp egress not found");
		goto ignore;
	}
	bpf_printk("%d: udp src=%d dst=%d len=%d",
	    tgid == NULL ? 0 : *tgid, bpf_ntohs(udp.source),
	    bpf_ntohs(udp.dest), bpf_ntohs(udp.len));

	cap_len = skb->len;
	/*
	 * verifier will complain, even with a skb->len
	 * check at the beginning.
	 */
	if (cap_len == 0)
		goto ignore;
	else if (cap_len > MAX_DNS_PACKET)
		cap_len = MAX_DNS_PACKET;

	event = get_event_buffer();
	if (event == NULL)
		goto ignore;

	event->hdr.type = EBPF_EVENT_NETWORK_DNS_PKT;
	event->hdr.ts = bpf_ktime_get_ns();
	event->hdr.ts_boot = bpf_ktime_get_boot_ns_helper();
	event->tgid = *tgid;
	event->cap_len = cap_len;
	event->orig_len = skb->len;
	event->direction = ingress ? EBPF_NETWORK_DIR_INGRESS : EBPF_NETWORK_DIR_EGRESS;

	ebpf_vl_fields__init(&event->vl_fields);
	field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_DNS_BODY);
	if (bpf_skb_load_bytes(skb, 0, field->data, cap_len))
		goto ignore;
	ebpf_vl_field__set_size(&event->vl_fields, field, cap_len);

	ebpf_ringbuf_write(&ringbuf, event, EVENT_SIZE(event), 0);

ignore:
	return (1);
}

SEC("cgroup_skb/egress")
int skb_egress(struct __sk_buff *skb)
{
	return skb_in_or_egress(skb, 0);
}

SEC("cgroup_skb/ingress")
int skb_ingress(struct __sk_buff *skb)
{
	return skb_in_or_egress(skb, 1);
}

int sk_maybe_save_tgid(struct bpf_sock *sk)
{
	u32 tgid;

	if (sk->protocol != IPPROTO_UDP)
		return (1);

	tgid = bpf_get_current_pid_tgid() >> 32;

	(void)bpf_map_update_elem(&sk_to_tgid, &sk, &tgid, BPF_ANY);

	return (1);
}

SEC("cgroup/sendmsg4")
int sendmsg4(struct bpf_sock_addr *sa)
{
	return sk_maybe_save_tgid(sa->sk);
}

SEC("cgroup/recvmsg4")
int recvmsg4(struct bpf_sock_addr *sa)
{
	return sk_maybe_save_tgid(sa->sk);
}

SEC("cgroup/connect4")
int connect4(struct bpf_sock_addr *sa)
{
	return sk_maybe_save_tgid(sa->sk);
}

SEC("cgroup/sock_create")
int sock_create(struct bpf_sock *sk)
{
	return sk_maybe_save_tgid(sk);
}

SEC("cgroup/sock_release")
int sock_release(struct bpf_sock *sk)
{
	(void)bpf_map_delete_elem(&sk_to_tgid, &sk);

	return (1);
}
