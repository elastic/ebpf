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

#include "Kerneldefs.h"
#include "TcFilterdefs.h"
#include "bpf_endian.h"
#include "bpf_helpers.h"

#ifndef __section
#define __section(NAME) __attribute__((section(NAME), used))
#endif

// you took NULL for granted didn't you :)
#define NULL 0

#define BPF_F_NO_PREALLOC (1U << 0)

/* Key of an a BPF_MAP_TYPE_LPM_TRIE entry */
struct bpf_lpm_trie_key {
    __u32 prefixlen; /* up to 32 for AF_INET, 128 for AF_INET6 */
    __u32 data;      /* Arbitrary size */
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 512);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
} allowed_IPs __section(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LPM_TRIE);
    __uint(key_size, 8);
    __uint(value_size, sizeof(int));
    __uint(max_entries, 256);
    __uint(pinning, LIBBPF_PIN_BY_NAME);
    __uint(map_flags, BPF_F_NO_PREALLOC);
} allowed_subnets __section(".maps");

__attribute__((always_inline)) static int allow_destination_IP(struct iphdr *ip)
{
    __u32 *elem                     = NULL;
    struct bpf_lpm_trie_key lpm_key = {
        .prefixlen = 32,
        .data      = ip->daddr,
    };

    /* Check allowed IPs map first */
    elem = bpf_map_lookup_elem(&allowed_IPs, &ip->daddr);
    if (elem) {
        /* IP is allowed */
        return 1;
    }

    /* Now check allowed subnets */
    elem = bpf_map_lookup_elem(&allowed_subnets, &lpm_key);
    if (!elem) {
        /* destination IP not within any allowed subnets - reject */
        return 0;
    } else {
        /* IP matches allowed subnet */
        return 1;
    }
}

__attribute__((always_inline)) static int allow_tcp_pkt_egress(struct tcphdr *tcp, struct iphdr *ip)
{
    /* TCP packets are currently only filtered based on destination IP */
    return allow_destination_IP(ip);
}

__attribute__((always_inline)) static int allow_udp_pkt_egress(struct udphdr *udp)
{
    if ((DNS_PORT == bpf_ntohs(udp->source)) || (DNS_PORT == bpf_ntohs(udp->dest))) {
        /* allow DNS port (both client and server) */
        return 1;
#if 0
        //TODO: check QDCOUNT==1 for sanity (it's always 1 for any DNS query)
        if ((__u8 *)(udp + 1) + 6 > skb->data_end) {
            return 0;
        }
        __u16 *dns = udp + 1;
#endif

    } else if (((DHCP_SERVER_PORT == bpf_ntohs(udp->dest)) &&
                (DHCP_CLIENT_PORT == bpf_ntohs(udp->source))) ||
               ((DHCP_CLIENT_PORT == bpf_ntohs(udp->dest)) &&
                (DHCP_SERVER_PORT == bpf_ntohs(udp->source)))) {
        /* allow DHCP ports (both client and server) */
        return 1;
    } else {
        /* drop packet */
        return 0;
    }
}

int classifier(struct __sk_buff *skb)
{
    struct ethhdr *eth = NULL;
    struct iphdr *ip   = NULL;
    void *data_end     = (void *)(long)skb->data_end;
    void *data         = (void *)(long)skb->data;
    __u32 eth_proto    = 0;
    int rv             = DROP_PACKET;

    if (data + sizeof(struct ethhdr) > data_end) {
        /* packet too small */
        rv = DROP_PACKET;
        goto out;
    }

    eth       = data;
    eth_proto = eth->h_proto;

    /* check L3 protocol */
    if (eth_proto == bpf_htons(ETH_P_ARP)) {
        /* allow ARP */
        rv = ALLOW_PACKET;
        goto out;
    }

    if (eth_proto != bpf_htons(ETH_P_IP)) {
        /* drop protocols other than IPv4 and ARP */
        rv = DROP_PACKET;
        goto out;
    }

    ip = data + sizeof(struct ethhdr);

    if (ip + 1 > data_end) {
        rv = DROP_PACKET;
        goto out;
    }

    if (4 != ip->version) {
        /* drop IPv6 */
        rv = DROP_PACKET;
        goto out;
    }

    if (5 != ip->ihl) {
        /* drop packets with IP options (5 == 20 bytes == min IP header size )
         */
        rv = DROP_PACKET;
        goto out;
    }

    if (ip->frag_off & PCKT_FRAGMENTED) {
        /* drop fragmented packets */
        rv = DROP_PACKET;
        goto out;
    }

    __u8 protocol = ip->protocol;

    if (protocol == IPPROTO_UDP) {
        /* handle UDP */
        struct udphdr *udp = ip + 1;
        if (udp + 1 > data_end) {
            rv = DROP_PACKET;
            goto out;
        }

        if (!allow_udp_pkt_egress(udp)) {
            rv = DROP_PACKET;
            goto out;
        } else {
            rv = ALLOW_PACKET;
            goto out;
        }
    } else if (protocol == IPPROTO_TCP) {
        /* handle TCP */
        struct tcphdr *tcp = ip + 1;
        if (tcp + 1 > data_end) {
            rv = DROP_PACKET;
            goto out;
        }

        if (!allow_tcp_pkt_egress(tcp, ip)) {
            rv = DROP_PACKET;
            goto out;
        } else {
            rv = ALLOW_PACKET;
            goto out;
        }
    } else if (protocol == IPPROTO_ICMP) {
        /* check IP exceptionlist for ICMP */
        if (!allow_destination_IP(ip)) {
            rv = DROP_PACKET;
            goto out;
        } else {
            rv = ALLOW_PACKET;
            goto out;
        }
    } else {
        /* drop other protos */
        rv = DROP_PACKET;
        goto out;
    }

out:
    return rv;
}

char __license[] __section("license") = "GPL";
