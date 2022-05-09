// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

typedef signed char __s8;

typedef unsigned char __u8;

typedef short int __s16;

typedef short unsigned int __u16;

typedef int __s32;

typedef unsigned int __u32;

typedef long long int __s64;

typedef long long unsigned int __u64;

typedef __s8 s8;

typedef __u8 u8;

typedef __s16 s16;

typedef __u16 u16;

typedef __s32 s32;

typedef __u32 u32;

typedef __s64 s64;

typedef __u64 u64;

typedef __u16 __le16;

typedef __u16 __be16;

typedef __u32 __be32;

typedef __u64 __be64;

typedef __u32 __wsum;

#ifdef __CHECKER__
#define __bitwise__ __attribute__((bitwise))
#else
#define __bitwise__
#endif
#define __bitwise __bitwise__

typedef __u16 __bitwise __le16;
typedef __u16 __bitwise __be16;
typedef __u32 __bitwise __le32;
typedef __u32 __bitwise __be32;
typedef __u64 __bitwise __le64;
typedef __u64 __bitwise __be64;

typedef __u16 __bitwise __sum16;
typedef __u32 __bitwise __wsum;

/* Standard well-defined IP protocols.  */
enum {
    IPPROTO_IP = 0, /* Dummy protocol for TCP               */
#define IPPROTO_IP IPPROTO_IP
    IPPROTO_ICMP = 1, /* Internet Control Message Protocol    */
#define IPPROTO_ICMP IPPROTO_ICMP
    IPPROTO_IGMP = 2, /* Internet Group Management Protocol   */
#define IPPROTO_IGMP IPPROTO_IGMP
    IPPROTO_IPIP = 4, /* IPIP tunnels (older KA9Q tunnels use 94) */
#define IPPROTO_IPIP IPPROTO_IPIP
    IPPROTO_TCP = 6, /* Transmission Control Protocol        */
#define IPPROTO_TCP IPPROTO_TCP
    IPPROTO_EGP = 8, /* Exterior Gateway Protocol            */
#define IPPROTO_EGP IPPROTO_EGP
    IPPROTO_PUP = 12, /* PUP protocol                         */
#define IPPROTO_PUP IPPROTO_PUP
    IPPROTO_UDP = 17, /* User Datagram Protocol               */
#define IPPROTO_UDP IPPROTO_UDP
    IPPROTO_IDP = 22, /* XNS IDP protocol                     */
#define IPPROTO_IDP IPPROTO_IDP
    IPPROTO_TP = 29, /* SO Transport Protocol Class 4        */
#define IPPROTO_TP IPPROTO_TP
    IPPROTO_DCCP = 33, /* Datagram Congestion Control Protocol */
#define IPPROTO_DCCP IPPROTO_DCCP
    IPPROTO_IPV6 = 41, /* IPv6-in-IPv4 tunnelling              */
#define IPPROTO_IPV6 IPPROTO_IPV6
    IPPROTO_RSVP = 46, /* RSVP Protocol                        */
#define IPPROTO_RSVP IPPROTO_RSVP
    IPPROTO_GRE = 47, /* Cisco GRE tunnels (rfc 1701,1702)    */
#define IPPROTO_GRE IPPROTO_GRE
    IPPROTO_ESP = 50, /* Encapsulation Security Payload protocol */
#define IPPROTO_ESP IPPROTO_ESP
    IPPROTO_AH = 51, /* Authentication Header protocol       */
#define IPPROTO_AH IPPROTO_AH
    IPPROTO_MTP = 92, /* Multicast Transport Protocol         */
#define IPPROTO_MTP IPPROTO_MTP
    IPPROTO_BEETPH = 94, /* IP option pseudo header for BEET     */
#define IPPROTO_BEETPH IPPROTO_BEETPH
    IPPROTO_ENCAP = 98, /* Encapsulation Header                 */
#define IPPROTO_ENCAP IPPROTO_ENCAP
    IPPROTO_PIM = 103, /* Protocol Independent Multicast       */
#define IPPROTO_PIM IPPROTO_PIM
    IPPROTO_COMP = 108, /* Compression Header Protocol          */
#define IPPROTO_COMP IPPROTO_COMP
    IPPROTO_SCTP = 132, /* Stream Control Transport Protocol    */
#define IPPROTO_SCTP IPPROTO_SCTP
    IPPROTO_UDPLITE = 136, /* UDP-Lite (RFC 3828)                  */
#define IPPROTO_UDPLITE IPPROTO_UDPLITE
    IPPROTO_MPLS = 137, /* MPLS in IP (RFC 4023)                */
#define IPPROTO_MPLS IPPROTO_MPLS
    IPPROTO_RAW = 255, /* Raw IP packets                       */
#define IPPROTO_RAW IPPROTO_RAW
    IPPROTO_MAX
};

/*
 *      IEEE 802.3 Ethernet magic constants.  The frame sizes omit the preamble
 *      and FCS/CRC (frame check sequence).
 */

#define ETH_ALEN 6         /* Octets in one ethernet addr   */
#define ETH_TLEN 2         /* Octets in ethernet type field */
#define ETH_HLEN 14        /* Total octets in header.       */
#define ETH_ZLEN 60        /* Min. octets in frame sans FCS */
#define ETH_DATA_LEN 1500  /* Max. octets in payload        */
#define ETH_FRAME_LEN 1514 /* Max. octets in frame sans FCS */
#define ETH_FCS_LEN 4      /* Octets in the FCS             */

#define ETH_MIN_MTU 68      /* Min IPv4 MTU per RFC791      */
#define ETH_MAX_MTU 0xFFFFU /* 65535, same as IP_MAX_MTU    */

/*
 *      These are the defined Ethernet Protocol ID's.
 */

#define ETH_P_LOOP 0x0060  /* Ethernet Loopback packet     */
#define ETH_P_PUP 0x0200   /* Xerox PUP packet             */
#define ETH_P_PUPAT 0x0201 /* Xerox PUP Addr Trans packet  */
#define ETH_P_TSN 0x22F0   /* TSN (IEEE 1722) packet       */
#define ETH_P_IP 0x0800    /* Internet Protocol packet     */
#define ETH_P_X25 0x0805   /* CCITT X.25                   */
#define ETH_P_ARP 0x0806   /* Address Resolution packet    */
#define ETH_P_BPQ                                                                                  \
    0x08FF                     /* G8BPQ AX.25 Ethernet Packet  [ NOT AN OFFICIALLY REGISTERED ID ] \
                                */
#define ETH_P_IEEEPUP 0x0a00   /* Xerox IEEE802.3 PUP packet */
#define ETH_P_IEEEPUPAT 0x0a01 /* Xerox IEEE802.3 PUP Addr Trans packet */
#define ETH_P_BATMAN                                                                               \
    0x4305                  /* B.A.T.M.A.N.-Advanced packet [ NOT AN OFFICIALLY REGISTERED ID ]    \
                             */
#define ETH_P_DEC 0x6000    /* DEC Assigned proto           */
#define ETH_P_DNA_DL 0x6001 /* DEC DNA Dump/Load            */
#define ETH_P_DNA_RC 0x6002 /* DEC DNA Remote Console       */
#define ETH_P_DNA_RT 0x6003 /* DEC DNA Routing              */
#define ETH_P_LAT 0x6004    /* DEC LAT                      */
#define ETH_P_DIAG 0x6005   /* DEC Diagnostics              */
#define ETH_P_CUST 0x6006   /* DEC Customer use             */
#define ETH_P_SCA 0x6007    /* DEC Systems Comms Arch       */
#define ETH_P_TEB 0x6558    /* Trans Ether Bridging         */
#define ETH_P_RARP 0x8035   /* Reverse Addr Res packet      */
#define ETH_P_ATALK 0x809B  /* Appletalk DDP                */
#define ETH_P_AARP 0x80F3   /* Appletalk AARP               */
#define ETH_P_8021Q 0x8100  /* 802.1Q VLAN Extended Header  */
#define ETH_P_ERSPAN 0x88BE /* ERSPAN type II               */
#define ETH_P_IPX 0x8137    /* IPX over DIX                 */
#define ETH_P_IPV6 0x86DD   /* IPv6 over bluebook           */
#define ETH_P_PAUSE 0x8808  /* IEEE Pause frames. See 802.3 31B */
#define ETH_P_SLOW 0x8809   /* Slow Protocol. See 802.3ad 43B */
#define ETH_P_WCCP                                                                                 \
    0x883E                    /* Web-cache coordination protocol                                   \
                               * defined in draft-wilson-wrec-wccp-v2-00.txt */
#define ETH_P_MPLS_UC 0x8847  /* MPLS Unicast traffic         */
#define ETH_P_MPLS_MC 0x8848  /* MPLS Multicast traffic       */
#define ETH_P_ATMMPOA 0x884c  /* MultiProtocol Over ATM       */
#define ETH_P_PPP_DISC 0x8863 /* PPPoE discovery messages     */
#define ETH_P_PPP_SES 0x8864  /* PPPoE session messages       */
#define ETH_P_LINK_CTL 0x886c /* HPNA, wlan link local tunnel */
#define ETH_P_ATMFATE                                                                              \
    0x8884                   /* Frame-based ATM Transport                                          \
                              * over Ethernet                                                      \
                              */
#define ETH_P_PAE 0x888E     /* Port Access Entity (IEEE 802.1X) */
#define ETH_P_AOE 0x88A2     /* ATA over Ethernet            */
#define ETH_P_8021AD 0x88A8  /* 802.1ad Service VLAN         */
#define ETH_P_802_EX1 0x88B5 /* 802.1 Local Experimental 1.  */
#define ETH_P_TIPC 0x88CA    /* TIPC                         */
#define ETH_P_MACSEC 0x88E5  /* 802.1ae MACsec */
#define ETH_P_8021AH 0x88E7  /* 802.1ah Backbone Service Tag */
#define ETH_P_MVRP 0x88F5    /* 802.1Q MVRP                  */
#define ETH_P_1588 0x88F7    /* IEEE 1588 Timesync */
#define ETH_P_NCSI 0x88F8    /* NCSI protocol                */
#define ETH_P_PRP 0x88FB     /* IEC 62439-3 PRP/HSRv0        */
#define ETH_P_FCOE 0x8906    /* Fibre Channel over Ethernet  */
#define ETH_P_IBOE 0x8915    /* Infiniband over Ethernet     */
#define ETH_P_TDLS 0x890D    /* TDLS */
#define ETH_P_FIP 0x8914     /* FCoE Initialization Protocol */
#define ETH_P_80221                                                                                \
    0x8917                    /* IEEE 802.21 Media Independent Handover Protocol                   \
                               */
#define ETH_P_HSR 0x892F      /* IEC 62439-3 HSRv1    */
#define ETH_P_NSH 0x894F      /* Network Service Header */
#define ETH_P_LOOPBACK 0x9000 /* Ethernet loopback packet, per IEEE 802.3 */
#define ETH_P_QINQ1 0x9100    /* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_QINQ2 0x9200    /* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_QINQ3 0x9300    /* deprecated QinQ VLAN [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_EDSA 0xDADA     /* Ethertype DSA [ NOT AN OFFICIALLY REGISTERED ID ] */
#define ETH_P_IFE 0xED3E      /* ForCES inter-FE LFB type */
#define ETH_P_AF_IUCV 0xFBFB  /* IBM af_iucv [ NOT AN OFFICIALLY REGISTERED ID ] */

#define ETH_P_802_3_MIN                                                                            \
    0x0600 /* If the value in the ethernet type is less than this value                            \
            * then the frame is Ethernet II. Else it is 802.3 */

#define TC_ACT_UNSPEC (-1)
#define TC_ACT_OK 0
#define TC_ACT_RECLASSIFY 1
#define TC_ACT_SHOT 2
#define TC_ACT_PIPE 3
#define TC_ACT_STOLEN 4
#define TC_ACT_QUEUED 5
#define TC_ACT_REPEAT 6
#define TC_ACT_REDIRECT 7
#define TC_ACT_JUMP 0x10000000

// TODO change to compiler flag ?
#define __LITTLE_ENDIAN_BITFIELD

struct iphdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 ihl : 4, version : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8 version : 4, ihl : 4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
    __u8 tos;
    __be16 tot_len;
    __be16 id;
    __be16 frag_off;
    __u8 ttl;
    __u8 protocol;
    __sum16 check;
    __be32 saddr;
    __be32 daddr;
    /*The options start here. */
};

#define __UAPI_DEF_IN6_ADDR 1

#if __UAPI_DEF_IN6_ADDR
struct in6_addr {
    union {
        __u8 u6_addr8[16];
#if __UAPI_DEF_IN6_ADDR_ALT
        __be16 u6_addr16[8];
        __be32 u6_addr32[4];
#endif
    } in6_u;
#define s6_addr in6_u.u6_addr8
#if __UAPI_DEF_IN6_ADDR_ALT
#define s6_addr16 in6_u.u6_addr16
#define s6_addr32 in6_u.u6_addr32
#endif
};

#endif /* __UAPI_DEF_IN6_ADDR */

struct ipv6hdr {
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u8 priority : 4, version : 4;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u8 version : 4, priority : 4;
#else
#error "Please fix <asm/byteorder.h>"
#endif
    __u8 flow_lbl[3];

    __be16 payload_len;
    __u8 nexthdr;
    __u8 hop_limit;

    struct in6_addr saddr;
    struct in6_addr daddr;
};

struct udphdr {
    __be16 source;
    __be16 dest;
    __be16 len;
    __sum16 check;
};

struct tcphdr {
    __be16 source;
    __be16 dest;
    __be32 seq;
    __be32 ack_seq;
#if defined(__LITTLE_ENDIAN_BITFIELD)
    __u16 res1 : 4, doff : 4, fin : 1, syn : 1, rst : 1, psh : 1, ack : 1, urg : 1, ece : 1,
        cwr : 1;
#elif defined(__BIG_ENDIAN_BITFIELD)
    __u16 doff : 4, res1 : 4, cwr : 1, ece : 1, urg : 1, ack : 1, psh : 1, rst : 1, syn : 1,
        fin : 1;
#else
#error "Adjust your <asm/byteorder.h> defines"
#endif
    __be16 window;
    __sum16 check;
    __be16 urg_ptr;
};

struct ethhdr {
    unsigned char h_dest[ETH_ALEN];   /* destination eth addr	*/
    unsigned char h_source[ETH_ALEN]; /* source ether addr	*/
    __be16 h_proto;                   /* packet type ID field	*/
} __attribute__((packed));

// This header might be included in userspace programs (e.g
// BPFTcFilterTests.cpp) where we want to share some definitions with kernel
// space programs (TcFilter.bpf.c). In this case, we need to gate some specific
// kernel definitions that are not needed in userspace.
#ifdef __KERNEL__
enum bpf_map_type {
    BPF_MAP_TYPE_UNSPEC,
    BPF_MAP_TYPE_HASH,
    BPF_MAP_TYPE_ARRAY,
    BPF_MAP_TYPE_PROG_ARRAY,
    BPF_MAP_TYPE_PERF_EVENT_ARRAY,
    BPF_MAP_TYPE_PERCPU_HASH,
    BPF_MAP_TYPE_PERCPU_ARRAY,
    BPF_MAP_TYPE_STACK_TRACE,
    BPF_MAP_TYPE_CGROUP_ARRAY,
    BPF_MAP_TYPE_LRU_HASH,
    BPF_MAP_TYPE_LRU_PERCPU_HASH,
    BPF_MAP_TYPE_LPM_TRIE,
    BPF_MAP_TYPE_ARRAY_OF_MAPS,
    BPF_MAP_TYPE_HASH_OF_MAPS,
    BPF_MAP_TYPE_DEVMAP,
    BPF_MAP_TYPE_SOCKMAP,
    BPF_MAP_TYPE_CPUMAP,
};
struct __sk_buff {
    __u32 len;
    __u32 pkt_type;
    __u32 mark;
    __u32 queue_mapping;
    __u32 protocol;
    __u32 vlan_present;
    __u32 vlan_tci;
    __u32 vlan_proto;
    __u32 priority;
    __u32 ingress_ifindex;
    __u32 ifindex;
    __u32 tc_index;
    __u32 cb[5];
    __u32 hash;
    __u32 tc_classid;
    __u32 data;
    __u32 data_end;
    __u32 napi_id;

    /* Accessed by BPF_PROG_TYPE_sk_skb types from here to ... */
    __u32 family;
    __u32 remote_ip4;    /* Stored in network byte order */
    __u32 local_ip4;     /* Stored in network byte order */
    __u32 remote_ip6[4]; /* Stored in network byte order */
    __u32 local_ip6[4];  /* Stored in network byte order */
    __u32 remote_port;   /* Stored in network byte order */
    __u32 local_port;    /* stored in host byte order */
                         /* ... here. */

    // Note: there are more fields but we don't use them
};
#else
#define __aligned_u64 __u64 __attribute__((aligned(8)))
#endif // __KERNEL__
