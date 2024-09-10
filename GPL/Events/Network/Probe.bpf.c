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

static int sock_dns_event_handle(struct sock *sk,
                                 struct msghdr *msg,
                                 enum ebpf_event_type evt_type,
                                 size_t size)
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
        goto out;
    }

    // deal with the iovec_iter type
    // newer kernels added a ubuf type to the iov_iter union,
    // which post-dates our vmlinux, but also they added ITER_UBUF as the
    // first value in the iter_type enum, which makes checking it a tad hard.
    // In theory we should be able to read from both types as long as we're careful

    struct iov_iter *from = &msg->msg_iter;

    u64 nr_segs    = get_iovec_nr_segs_or_max(from);
    u64 iovec_size = BPF_CORE_READ(from, count);

    const struct iovec *iov;
    if (FIELD_OFFSET(iov_iter, __iov))
        iov = (const struct iovec *)((char *)from + FIELD_OFFSET(iov_iter, __iov));
    else if (bpf_core_field_exists(from->iov))
        iov = BPF_CORE_READ(from, iov);
    else {
        bpf_printk("unknown offset in iovec structure, bug?");
        goto out;
    }

    if (nr_segs == 1) {
        // actually read in raw packet data
        // use the retvalue of recvmsg/the count value of sendmsg instead of the the iovec count.
        // The count of the iovec in udp_recvmsg is the size of the buffer, not the size of the
        // bytes read.
        void *base         = BPF_CORE_READ(iov, iov_base);
        event->pkts[0].len = size;
        // make verifier happy, we can't have an out-of-bounds write
        if (size > MAX_DNS_PACKET) {
            bpf_printk("size of packet (%d) exceeds max packet size (%d), skipping", size,
                       MAX_DNS_PACKET);
            goto out;
        }
        // TODO: This will fail on recvmsg calls where the peek flag has been set.
        // Changes to the udp_recvmsg function call in 5.18 make it a bit annoying to get the
        // flags argument portably. So let it fail instead of manually skipping peek calls.
        long readok = bpf_probe_read(event->pkts[0].pkt, size, base);
        if (readok != 0) {
            bpf_printk("invalid read from iovec structure: %d", readok);
            goto out;
        }
    } else {
        // we have multiple segments.
        // Can't rely on the size value from the function, revert to the iovec size to read into the
        // buffer
        // In practice, I haven't seen a DNS packet with more than one iovec segment;
        // the size of UDP DNS packet is limited to 512 bytes, so not sure if this is possible?
        for (int seg = 0; seg < nr_segs; seg++) {
            if (seg >= MAX_NR_SEGS)
                goto out;

            struct iovec *cur_iov = (struct iovec *)&iov[seg];
            void *base            = BPF_CORE_READ(cur_iov, iov_base);
            size_t bufsize        = BPF_CORE_READ(cur_iov, iov_len);
            event->pkts[seg].len  = bufsize;
            if (bufsize > sizeof(event->pkts[seg].pkt)) {
                goto out;
            }
            bpf_probe_read(event->pkts[seg].pkt, bufsize, base);
        }
    }

    event->hdr.type = EBPF_EVENT_NETWORK_DNS_PKT;
    event->udp_evt  = evt_type;
    bpf_ringbuf_submit(event, 0);
    return 0;

out:
    bpf_ringbuf_discard(event, 0);
    return 0;
}

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

/*
=============================== TEST CODE ===============================

Testing alternate code. This section will not be merged, or will be cleaned up.
*/

static int handle_consume(struct sk_buff *skb, int len, enum ebpf_event_type evt_type)
{

    if (ebpf_events_is_trusted_pid())
        return 0;

    struct ebpf_dns_event *event = bpf_ringbuf_reserve(&ringbuf, sizeof(*event), 0);
    if (!event)
        return 0;

    // read from skbuf
    unsigned char *data = BPF_CORE_READ(skb, head);
    // get lengths
    u16 net_header_offset       = BPF_CORE_READ(skb, network_header);
    u16 transport_header_offset = BPF_CORE_READ(skb, transport_header);

    u8 iphdr_first_byte = 0;
    bpf_core_read(&iphdr_first_byte, 1, data + net_header_offset);
    iphdr_first_byte = iphdr_first_byte >> 4;

    u8 proto = 0;
    if (iphdr_first_byte == 4) {
        struct iphdr ip_hdr;
        bpf_core_read(&ip_hdr, sizeof(struct iphdr), data + net_header_offset);

        proto = ip_hdr.protocol;
        bpf_probe_read(event->net.saddr, 4, (void *)&ip_hdr.saddr);
        bpf_probe_read(event->net.daddr, 4, (void *)&ip_hdr.daddr);

    } else if (iphdr_first_byte == 6) {
        struct ipv6hdr ip6_hdr;
        bpf_core_read(&ip6_hdr, sizeof(struct ipv6hdr), data + net_header_offset);
        proto = ip6_hdr.nexthdr;

        bpf_probe_read(event->net.saddr6, 16, ip6_hdr.saddr.in6_u.u6_addr8);
        bpf_probe_read(event->net.daddr6, 16, ip6_hdr.daddr.in6_u.u6_addr8);
    }

    if (proto != IPPROTO_UDP) {
        goto out;
    }

    struct udphdr udp_hdr;
    bpf_core_read(&udp_hdr, sizeof(struct udphdr), data + transport_header_offset);
    event->net.dport = bpf_ntohs(udp_hdr.dest);
    event->net.sport = bpf_ntohs(udp_hdr.source);

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ebpf_pid_info__fill(&event->pids, task);
    bpf_get_current_comm(event->comm, TASK_COMM_LEN);
    event->hdr.ts = bpf_ktime_get_ns();

    // filter out non-dns packets
    if (event->net.sport != 53 && event->net.dport != 53) {
        bpf_printk("not a dns packet...");
        goto out;
    }

    // constrain the read size to make the verifier happy
    long readsize = BPF_CORE_READ(skb, len);
    if (readsize > MAX_DNS_PACKET) {
        readsize = MAX_DNS_PACKET;
    }

    // udp_send_skb includes the IP and UDP header, so offset
    long offset = transport_header_offset + sizeof(struct udphdr);

    long ret = bpf_probe_read_kernel(event->pkts[0].pkt, readsize, data + offset);
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

SEC("fentry/ip_send_skb")
int BPF_PROG(fentry__ip_send_skb, struct net *net, struct sk_buff *skb)
{
    return handle_consume(skb, skb->len, EBPF_EVENT_NETWORK_UDP_SENDMSG);
}

SEC("fexit/skb_consume_udp")
int BPF_PROG(fexit__skb_consume_udp, struct sock *sk, struct sk_buff *skb, int len)
{
    // skip peek operations
    bpf_printk("consume len: %d", len);
    if (len < 0) {
        return 0;
    }
    return handle_consume(skb, len, EBPF_EVENT_NETWORK_UDP_RECVMSG);
}

SEC("kprobe/ip_send_skb")
int BPF_KPROBE(kprobe__ip_send_udp, struct net *net, struct sk_buff *skb)
{
    long len = BPF_CORE_READ(skb, len);
    return handle_consume(skb, len, EBPF_EVENT_NETWORK_UDP_SENDMSG);
}

SEC("kprobe/skb_consume_udp")
int BPF_KPROBE(kprobe__skb_consume_udp, struct net *net, struct sk_buff *skb)
{
    // return handle_consume(skb, len, EBPF_EVENT_NETWORK_UDP_SENDMSG);
    struct udp_ctx kctx;

    // I suspect that using the PID_TID isn't the most reliable way to map the sockets/iters
    // not sure what else we could use that's accessable from the kretprobe, though.
    u64 pid_tid = bpf_get_current_pid_tgid();

    long iter_err = bpf_probe_read(&kctx.skb, sizeof(kctx.skb), &skb);
    if (iter_err != 0) {
        bpf_printk("error reading skb in skb_consume_skb: %d", iter_err);
        return 0;
    }

    long update_err = bpf_map_update_elem(&pkt_ctx, &pid_tid, &kctx, BPF_ANY);
    if (update_err != 0) {
        bpf_printk("error updating context map in udp_recvmsg: %d", update_err);
        return 0;
    }

    return 0;
}

SEC("kretprobe/skb_consume_udp")
int BPF_KRETPROBE(kretprobe__skb_consume_udp, int ret)
{
    u64 pid_tid = bpf_get_current_pid_tgid();
    void *vctx  = bpf_map_lookup_elem(&pkt_ctx, &pid_tid);

    struct udp_ctx kctx;
    long read_err = bpf_probe_read(&kctx, sizeof(kctx), vctx);
    if (read_err != 0) {
        bpf_printk("error reading back context in skb_consume_skb: %d", read_err);
        return 0;
    }

    return handle_consume(kctx.skb, ret, EBPF_EVENT_NETWORK_UDP_RECVMSG);
}

/*
=============================== DNS probes ===============================
*/

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe__udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    return sock_dns_event_handle(sk, msg, EBPF_EVENT_NETWORK_UDP_SENDMSG, size);
}

// We can't get the arguments from a kretprobe, so instead save off the pointer in
// in the kprobe, then fetch the pointer from a context map in the kretprobe

// SEC("kprobe/udp_recvmsg")
// int BPF_KPROBE(kprobe__udp_recvmsg, struct sock *sk, struct msghdr *msg)
// {
//     struct udp_ctx kctx;

//     // I suspect that using the PID_TID isn't the most reliable way to map the sockets/iters
//     // not sure what else we could use that's accessable from the kretprobe, though.
//     u64 pid_tid = bpf_get_current_pid_tgid();

//     long iter_err = bpf_probe_read(&kctx.hdr, sizeof(kctx.hdr), &msg);
//     if (iter_err != 0) {
//         bpf_printk("error reading msg_iter in udp_recvmsg: %d", iter_err);
//         return 0;
//     }

//     long sk_err = bpf_probe_read(&kctx.sk, sizeof(kctx.sk), &sk);
//     if (sk_err != 0) {
//         bpf_printk("error reading msg_iter in udp_recvmsg: %d", sk_err);
//         return 0;
//     }

//     long update_err = bpf_map_update_elem(&pkt_ctx, &pid_tid, &kctx, BPF_ANY);
//     if (update_err != 0) {
//         bpf_printk("error updating context map in udp_recvmsg: %d", update_err);
//         return 0;
//     }

//     return 0;
// }

// SEC("kretprobe/udp_recvmsg")
// int BPF_KRETPROBE(kretprobe__udp_recvmsg, int ret)
// {

//     u64 pid_tid = bpf_get_current_pid_tgid();
//     void *vctx  = bpf_map_lookup_elem(&pkt_ctx, &pid_tid);

//     struct udp_ctx kctx;
//     long read_err = bpf_probe_read(&kctx, sizeof(kctx), vctx);
//     if (read_err != 0) {
//         bpf_printk("error reading back context in udp_recvmsg: %d", read_err);
//     }

//     return sock_dns_event_handle(kctx.sk, kctx.hdr, EBPF_EVENT_NETWORK_UDP_RECVMSG, ret);
// }

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
