// SPDX-License-Identifier: GPL-3.0-only

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


#include "Kerneldefs.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#define PCKT_FRAGMENTED 65343

// you took NULL for granted didn't you :)
#define NULL 0

#define DROP_PACKET TC_ACT_SHOT
#define ALLOW_PACKET TC_ACT_UNSPEC

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 512);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} allowed_IPs __section(".maps");

__attribute__((always_inline))
static int
allow_tcp_pkt_egress(
    struct tcphdr *tcp,
    struct iphdr *ip)
{
    __u32 *elem = NULL;

    elem = bpf_map_lookup_elem(&allowed_IPs, &ip->daddr);
    if (!elem)
    {
        /* destination IP not in allowlist - reject */
        return 0;
    }
    else
    {
        /* IP is allowed */
        return 1;
    }
}

__attribute__((always_inline))
static int
allow_udp_pkt_egress(
    struct udphdr *udp)
{
    if (bpf_ntohs(udp->dest) == 53)
    {
        /* allow DNS port */
        return 1;
#if 0
        //TODO: check QDCOUNT==1 for sanity (it's always 1 for any DNS query)
        if ((__u8 *)(udp + 1) + 6 > skb->data_end) {
            return 0;
        }
        __u16 *dns = udp + 1;
#endif

    }
    //TODO DHCP?

    /* drop packet */
    return 0;
}

int
classifier(
    struct __sk_buff *skb)
{
    struct ethhdr *eth = NULL;
    struct iphdr *ip = NULL;
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    __u32 eth_proto = 0;
    int rv = DROP_PACKET;

    if (data + sizeof(struct ethhdr) > data_end)
    {
        /* packet too small */
        rv = DROP_PACKET;
        goto out;
    }

    eth = data;
    eth_proto = eth->h_proto;

    /* check L3 protocol */
    if (eth_proto == bpf_htons(ETH_P_ARP))
    {
        /* allow ARP */
        rv = ALLOW_PACKET;
        goto out;
    }

    if (eth_proto != bpf_htons(ETH_P_IP))
    {
        /* drop protocols other than IPv4 and ARP */
        rv = DROP_PACKET;
        goto out;
    }

    ip = data + sizeof(struct ethhdr);

    if (ip + 1 > data_end)
    {
        rv = DROP_PACKET;
        goto out;
    }

    if (ip->version != 4)
    {
        /* drop IPv6 */
        rv = DROP_PACKET;
        goto out;
    }

    if (ip->ihl != 5)
    {
        /* drop packets with IP options (5 == 20 bytes == min IP header size ) */
        rv = DROP_PACKET;
        goto out;
    }

    if (ip->frag_off & PCKT_FRAGMENTED)
    {
        /* drop fragmented packets */
        rv = DROP_PACKET;
        goto out;
    }

    __u8 protocol = ip->protocol;

    if (protocol == IPPROTO_ICMP)
    {
        /* drop ICMP */
        rv = DROP_PACKET;
        goto out;
    }

    if (protocol == IPPROTO_UDP)
    {
        /* handle UDP */
        struct udphdr *udp = ip + 1;
        if (udp + 1 > data_end)
        {
            rv = DROP_PACKET;
            goto out;
        }

        if (!allow_udp_pkt_egress(udp))
        {
            rv = DROP_PACKET;
            goto out;
        }
        else
        {
            rv = ALLOW_PACKET;
            goto out;
        }
    }
    else if (protocol == IPPROTO_TCP)
    {
        /* handle TCP */
        struct tcphdr *tcp = ip + 1;
        if (tcp + 1 > data_end)
        {
            rv = DROP_PACKET;
            goto out;
        }

        if (!allow_tcp_pkt_egress(tcp, ip))
        {
            rv = DROP_PACKET;
            goto out;
        }
        else
        {
            rv = ALLOW_PACKET;
            goto out;
        }
    }
    else
    {
        /* drop other protos */
        rv = DROP_PACKET;
        goto out;
    }

out:
    return rv;
}

char __license[] __section("license") = "GPL";

