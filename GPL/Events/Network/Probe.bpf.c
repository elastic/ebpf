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

#ifdef notyet
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
#endif
int skb_in_or_egress(struct __sk_buff *skb, int ingress)
{
    struct udphdr udp;
    struct bpf_sock *sk;
    u32 *tgid, cap_len, zero = 0;
    u64 *sk_addr;
    struct ebpf_dns_event *event;
    struct ebpf_varlen_field *field;

    if (skb->family != AF_INET && skb->family != AF_INET6)
        goto ignore;
    if ((sk = skb->sk) == NULL)
        goto ignore;
    if ((sk = bpf_sk_fullsock(sk)) == NULL)
        goto ignore;
    if (sk->protocol != IPPROTO_UDP)
        goto ignore;

    if (sk->family == AF_INET) {
        struct iphdr ip;

        if (bpf_skb_load_bytes(skb, 0, &ip, sizeof(ip))) {
            bpf_printk("copy error 1");
            goto ignore;
        }
        if (ip.protocol != IPPROTO_UDP)
            goto ignore;
        if (bpf_skb_load_bytes(skb, ip.ihl << 2, &udp, sizeof(udp))) {
            bpf_printk("copy error 2");
            goto ignore;
        }
    } else {
        goto ignore;
    }
#ifdef notyet
    else if (sk->family == AF_INET6)
    {
        int t_off;

        t_off = skb_peel_nexthdr(skb, NEXTHDR_UDP);
        if (t_off == -1)
            goto ignore;

        if (bpf_skb_load_bytes(skb, t_off, &udp, sizeof(udp))) {
            bpf_printk("copy error 4");
            goto ignore;
        }
    }
#endif

    if (bpf_ntohs(udp.dest) != 53 && bpf_ntohs(udp.source) != 53)
        goto ignore;

    /*
     * Needed for kernels prior to f79efcb0075a20633cbf9b47759f2c0d538f78d8
     * bpf: Permits pointers on stack for helper calls
     */
    sk_addr = bpf_map_lookup_elem(&scratch64, &zero);
    if (sk_addr == NULL)
        goto ignore;
    *sk_addr = (u64)sk;
    tgid     = bpf_map_lookup_elem(&sk_to_tgid, sk_addr);
    if (tgid == NULL) {
        bpf_printk("udp egress not found");
        goto ignore;
    }
    bpf_printk("%d: udp src=%d dst=%d len=%d", tgid == NULL ? 0 : *tgid, bpf_ntohs(udp.source),
               bpf_ntohs(udp.dest), bpf_ntohs(udp.len));

    cap_len = skb->len;
    /*
     * verifier will complain, even with a skb->len
     * check at the beginning.
     */
    if (cap_len > MAX_DNS_PACKET)
        cap_len = MAX_DNS_PACKET;

    /*
     * Yes this code is weird, but it convinces old verifiers (5.10), don't
     * blame me, be sure to test 5.10 if you change it.  The minimal packet
     * should be iphlen + udphlen + 12(dns header size). Old verifiers
     * (5.10) are very sensitive here and a non constant right expression
     * (since iphlen is not constant due to options) fails. Do what we can
     * and filter the remaining bad packets in userland, same applies to
     * ipv6. Also be careful with `if cap_len > 0`, as clang will compile it
     * to a JNZ, which doesn't adjust umin, causing the
     * bpf_skb_load_bytes() down below to think cap_len can be zero.
     */
    if (cap_len >= (sizeof(struct iphdr) + sizeof(udp) + 12)) {
        event = get_event_buffer();
        if (event == NULL)
            goto ignore;

        event->hdr.type    = EBPF_EVENT_NETWORK_DNS_PKT;
        event->hdr.ts      = bpf_ktime_get_ns();
        event->hdr.ts_boot = bpf_ktime_get_boot_ns_helper();
        event->tgid        = *tgid;
        event->cap_len     = cap_len;
        event->orig_len    = skb->len;
        event->direction   = ingress ? EBPF_NETWORK_DIR_INGRESS : EBPF_NETWORK_DIR_EGRESS;

        ebpf_vl_fields__init(&event->vl_fields);
        field = ebpf_vl_field__add(&event->vl_fields, EBPF_VL_FIELD_DNS_BODY);
        if (bpf_skb_load_bytes(skb, 0, field->data, cap_len))
            goto ignore;
        ebpf_vl_field__set_size(&event->vl_fields, field, cap_len);

        ebpf_ringbuf_write(&ringbuf, event, EVENT_SIZE(event), 0);
    }

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
    u32 tgid, zero = 0;
    u64 *sk_addr;

    if (sk->protocol != IPPROTO_UDP)
        return (1);

    tgid = bpf_get_current_pid_tgid() >> 32;

    /*
     * Needed for kernels prior to f79efcb0075a20633cbf9b47759f2c0d538f78d8
     * bpf: Permits pointers on stack for helper calls
     */
    sk_addr = bpf_map_lookup_elem(&scratch64, &zero);
    if (sk_addr == NULL)
        return (1);
    *sk_addr = (u64)sk;
    if (bpf_map_update_elem(&sk_to_tgid, sk_addr, &tgid, BPF_ANY) == 0)
        bpf_printk("sk %p saved", sk);

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
    u32 zero = 0;
    u64 *sk_addr;

    if (sk->protocol != IPPROTO_UDP)
        return (1);

    /*
     * Needed for kernels prior to f79efcb0075a20633cbf9b47759f2c0d538f78d8
     * bpf: Permits pointers on stack for helper calls
     */
    sk_addr = bpf_map_lookup_elem(&scratch64, &zero);
    if (sk_addr == NULL)
        return (1);
    *sk_addr = (u64)sk;
    if (bpf_map_delete_elem(&sk_to_tgid, sk_addr) == 0)
        bpf_printk("%p deleted", sk);

    return (1);
}
