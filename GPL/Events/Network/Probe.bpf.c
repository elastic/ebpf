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
=============================== DNS probes ===============================
*/

SEC("fentry/udp_sendmsg")
int BPF_PROG(fentry__udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    return sock_dns_event_handle(sk, msg, EBPF_EVENT_NETWORK_UDP_SENDMSG, size);
}

SEC("fexit/udp_recvmsg")
int BPF_PROG(fexit__udp_recvmsg)
{

    // 5.18 changed the function args for udp_recvmsg,
    // so we have to do this to fetch the value of the `flags` arg.
    // obviously if the args change again this can fail.
    u64 flags   = 0;
    u64 nr_args = bpf_get_func_arg_cnt(ctx);
    if (nr_args == 5) {
        bpf_get_func_arg(ctx, 3, &flags);
    } else if (nr_args == 6) {
        bpf_get_func_arg(ctx, 4, &flags);
    }
    // check the peeking flag; if set to peek, the msghdr won't contain any data
    // Still trying to get this to work portably.
    if (flags & MSG_PEEK) {
        return 0;
    }
    // bpf_get_func_arg_cnt()
    struct sock *sk    = (void *)ctx[0];
    struct msghdr *msg = (void *)ctx[1];
    u64 ret            = 0;
    bpf_get_func_ret(ctx, &ret);
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    // struct msghdr* msg = (struct msghdr*)PT_REGS_PARM2(regs);
    bpf_printk("retval: %d", regs_ret);
    // return 0;
    return sock_dns_event_handle(sk, msg, EBPF_EVENT_NETWORK_UDP_RECVMSG, ret);
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe__udp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size)
{
    return sock_dns_event_handle(sk, msg, EBPF_EVENT_NETWORK_UDP_SENDMSG, size);
}

// We can't get the arguments from a kretprobe, so instead save off the pointer in
// in the kprobe, then fetch the pointer from a context map in the kretprobe

SEC("kprobe/udp_recvmsg")
int BPF_KPROBE(kprobe__udp_recvmsg, struct sock *sk, struct msghdr *msg)
{
    struct udp_ctx kctx;

    // I suspect that using the PID_TID isn't the most reliable way to map the sockets/iters
    // not sure what else we could use that's accessable from the kretprobe, though.
    u64 pid_tid = bpf_get_current_pid_tgid();

    long iter_err = bpf_probe_read(&kctx.hdr, sizeof(kctx.hdr), &msg);
    if (iter_err != 0) {
        bpf_printk("error reading msg_iter in udp_recvmsg: %d", iter_err);
        return 0;
    }

    long sk_err = bpf_probe_read(&kctx.sk, sizeof(kctx.sk), &sk);
    if (sk_err != 0) {
        bpf_printk("error reading msg_iter in udp_recvmsg: %d", sk_err);
        return 0;
    }

    long update_err = bpf_map_update_elem(&pkt_ctx, &pid_tid, &kctx, BPF_ANY);
    if (update_err != 0) {
        bpf_printk("error updating context map in udp_recvmsg: %d", update_err);
        return 0;
    }

    return 0;
}

SEC("kretprobe/udp_recvmsg")
int BPF_KRETPROBE(kretprobe__udp_recvmsg, int ret)
{
    bpf_printk("in kretprobe udp_recvmsg....");

    u64 pid_tid = bpf_get_current_pid_tgid();
    void *vctx  = bpf_map_lookup_elem(&pkt_ctx, &pid_tid);

    struct udp_ctx kctx;
    long read_err = bpf_probe_read(&kctx, sizeof(kctx), vctx);
    if (read_err != 0) {
        bpf_printk("error reading back context in udp_recvmsg: %d", read_err);
    }

    return sock_dns_event_handle(kctx.sk, kctx.hdr, EBPF_EVENT_NETWORK_UDP_RECVMSG, ret);
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
