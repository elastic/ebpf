//TODO license

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

    if (data + sizeof(struct ethhdr) > data_end)
    {
        /* packet too small */
        goto drop_packet;
    }

    eth = data;
    eth_proto = eth->h_proto;

    /* check L3 protocol */
    if (eth_proto == bpf_htons(ETH_P_ARP))
    {
        /* allow ARP */
        goto allow_packet;
    }

    if (eth_proto != bpf_htons(ETH_P_IP))
    {
        /* drop protocols other than IPv4 and ARP */
        goto drop_packet;
    }

    ip = data + sizeof(struct ethhdr);

    if (ip + 1 > data_end)
    {
        goto drop_packet;
    }

    if (ip->version != 4)
    {
        /* drop IPv6 */
        goto drop_packet;
    }

    if (ip->ihl != 5)
    {
        /* drop packets with IP options (5 == 20 bytes == min IP header size ) */
        goto drop_packet;
    }

    if (ip->frag_off & PCKT_FRAGMENTED)
    {
        /* drop fragmented packets */
        goto drop_packet;
    }

    __u8 protocol = ip->protocol;

    if (protocol == IPPROTO_ICMP)
    {
        /* drop ICMP */
        goto drop_packet;
    }

    if (protocol == IPPROTO_UDP)
    {
        /* handle UDP */
        struct udphdr *udp = ip + 1;
        if (udp + 1 > data_end)
        {
            goto drop_packet;
        }

        if (!allow_udp_pkt_egress(udp))
        {
            goto drop_packet;
        }
        else
        {
            goto allow_packet;
        }
    }
    else if (protocol == IPPROTO_TCP)
    {
        /* handle TCP */
        struct tcphdr *tcp = ip + 1;
        if (tcp + 1 > data_end)
        {
            goto drop_packet;
        }

        if (!allow_tcp_pkt_egress(tcp, ip))
        {
            goto drop_packet;
        }
        else
        {
            goto allow_packet;
        }
    }
    else
    {
        /* drop other protos */
        goto drop_packet;
    }

drop_packet:
    /* reject everything else */
    return TC_ACT_SHOT;

allow_packet:
    return TC_ACT_UNSPEC;
}

char __license[] __section("license") = "GPL";

