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

#ifndef EBPF_EVENTPROBE_NETWORK_H
#define EBPF_EVENTPROBE_NETWORK_H

// linux/socket.h
#define AF_INET 2
#define AF_INET6 10

static int
ebpf_sock_info__fill(enum ebpf_event_type typ, struct ebpf_net_info *net, struct sock *sk)
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

    if (typ == EBPF_EVENT_NETWORK_CONNECTION_CLOSED) {
        struct tcp_sock *tp           = (struct tcp_sock *)sk;
        net->tcp.close.bytes_sent     = BPF_CORE_READ(tp, bytes_sent);
        net->tcp.close.bytes_received = BPF_CORE_READ(tp, bytes_received);
    }

out:
    return err;
}

#endif // EBPF_EVENTPROBE_NETWORK_H
