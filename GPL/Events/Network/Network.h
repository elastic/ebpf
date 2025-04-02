// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#ifndef EBPF_EVENTPROBE_NETWORK_H
#define EBPF_EVENTPROBE_NETWORK_H

// linux/socket.h
#define AF_INET 2
#define AF_INET6 10

static int ebpf_sock_info__fill(struct ebpf_net_info *net, struct sock *sk)
{
    int err = 0;

    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);
    switch (family) {
    case AF_INET:
        err = BPF_CORE_READ_INTO(&net->saddr, sk, __sk_common.skc_rcv_saddr);
        if (err) {
            bpf_printk("AF_INET: error while reading saddr");
            goto out;
        }

        err = BPF_CORE_READ_INTO(&net->daddr, sk, __sk_common.skc_daddr);
        if (err) {
            bpf_printk("AF_INET: error while reading daddr");
            goto out;
        }

        net->family = EBPF_NETWORK_EVENT_AF_INET;
        break;
    case AF_INET6:
        err = BPF_CORE_READ_INTO(&net->saddr6, sk, __sk_common.skc_v6_rcv_saddr);
        if (err) {
            bpf_printk("AF_INET6: error while reading saddr");
            goto out;
        }

        err = BPF_CORE_READ_INTO(&net->daddr6, sk, __sk_common.skc_v6_daddr);
        if (err) {
            bpf_printk("AF_INET6: error while reading daddr");
            goto out;
        }

        net->family = EBPF_NETWORK_EVENT_AF_INET6;
        break;
    default:
        err = -1;
        goto out;
    }

    struct inet_sock *inet = (struct inet_sock *)sk;
    u16 sport              = BPF_CORE_READ(inet, inet_sport);
    net->sport             = bpf_ntohs(sport);
    u16 dport              = BPF_CORE_READ(sk, __sk_common.skc_dport);
    net->dport             = bpf_ntohs(dport);
    net->netns             = BPF_CORE_READ(sk, __sk_common.skc_net.net, ns.inum);

    /*
     * Old kernels, 4.18x have a bitmap for sk_protocol, in that case it's a
     * 32bit, we read it on a short, and the protocol is the byte on the upper
     * half.
     */
    u16 proto = BPF_CORE_READ(sk, sk_protocol);
    if (bpf_core_field_size(sk->sk_protocol) == 4)
        proto >>= 8;
    switch (proto) {
    case IPPROTO_TCP:
        net->transport = EBPF_NETWORK_EVENT_TRANSPORT_TCP;
        break;
    default:
        err = -1;
        goto out;
    }

out:
    return err;
}

static int ebpf_network_event__fill(struct ebpf_net_event *evt, struct sock *sk)
{
    int err = 0;

    if (ebpf_sock_info__fill(&evt->net, sk)) {
        err = -1;
        goto out;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    ebpf_pid_info__fill(&evt->pids, task);
    bpf_get_current_comm(evt->comm, TASK_COMM_LEN);
    evt->hdr.ts      = bpf_ktime_get_ns();
    evt->hdr.ts_boot = bpf_ktime_get_boot_ns_helper();

out:
    return err;
}

#endif // EBPF_EVENTPROBE_NETWORK_H
