// kernel headers
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/pkt_cls.h>
#include <linux/swab.h>
#include <arpa/inet.h>

// local headers
#include "kerneldefs.h"
#include "bpf_helpers.h"
#include "bpf_endian.h"

#ifndef __section
# define __section(NAME)                  \
   __attribute__((section(NAME), used))
#endif

#define PCKT_FRAGMENTED 65343

// you took NULL for granted didn't you :)
#define NULL 0

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
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
            return TC_ACT_SHOT;
        }
        __u16 *dns = udp + 1;
#endif

    }
    //TODO DHCP?

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

    if (data + sizeof(struct ethhdr) > data_end)
    {
        /* packet too small */
        return TC_ACT_SHOT;
    }

    eth = data;
    eth_proto = eth->h_proto;

    /* check L3 protocol */
    if (eth_proto == bpf_htons(ETH_P_ARP))
    {
        /* allow ARP */
        return TC_ACT_UNSPEC;
    }

    if (eth_proto != bpf_htons(ETH_P_IP))
    {
        /* drop protocols other than IPv4 and ARP */
        return TC_ACT_SHOT;
    }

    ip = data + sizeof(struct ethhdr);

    if (ip + 1 > data_end)
    {
        return TC_ACT_SHOT;
    }

    if (ip->version != 4)
    {
        /* drop IPv6 */
        return TC_ACT_SHOT;
    }

    if (ip->ihl != 5)
    {
        /* drop packets with IP options (5 == 20 bytes == min IP header size ) */
        return TC_ACT_SHOT;
    }

    if (ip->frag_off & PCKT_FRAGMENTED)
    {
        /* drop fragmented packets */
        return TC_ACT_SHOT;
    }

    __u8 protocol = ip->protocol;

    if (protocol == IPPROTO_ICMP)
    {
        /* drop ICMP */
        return TC_ACT_SHOT;
    }

    if (protocol == IPPROTO_UDP)
    {
        /* handle UDP */
        struct udphdr *udp = ip + 1;
        if (udp + 1 > data_end)
        {
            return TC_ACT_SHOT;
        }

        if (!allow_udp_pkt_egress(udp))
        {
            return TC_ACT_SHOT;
        }
        else
        {
            return TC_ACT_UNSPEC;
        }
    }
    else if (protocol == IPPROTO_TCP)
    {
        /* handle TCP */
        struct tcphdr *tcp = ip + 1;
        if (tcp + 1 > data_end)
        {
            return TC_ACT_SHOT;
        }

        if (!allow_tcp_pkt_egress(tcp, ip))
        {
            return TC_ACT_SHOT;
        }
        else
        {
            return TC_ACT_UNSPEC;
        }
    }
    else
    {
        /* drop other protos */
        return TC_ACT_SHOT;
    }

    /* reject everything else */
    return TC_ACT_SHOT;
}

char __license[] __section("license") = "GPL";

