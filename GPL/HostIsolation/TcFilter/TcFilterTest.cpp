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
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/pkt_cls.h>

#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf.h>

#include <sched.h>
#include <sys/resource.h>

#include <gtest/gtest.h>

#include "TcFilterdefs.h"

#define OBJECT_PATH_ENV_VAR "ELASTIC_EBPF_TC_FILTER_OBJ_PATH"
#define DEFAULT_OBJECT_PATH "TcFilter.bpf.o"
#define CLASSIFIER_SECTION_NAME "classifier"

#define MAGIC_BYTES 123
#define __packed __attribute__((__packed__))
struct packet_v4
{
    struct ethhdr eth;
    struct iphdr iph;
    struct tcphdr tcp;
} __packed;

struct packet_v4_udp
{
    struct ethhdr eth;
    struct iphdr iph;
    struct udphdr udp;
} __packed;

struct packet_v6 {
    struct ethhdr eth;
    struct ipv6hdr iph;
    struct tcphdr tcp;
} __packed;

class TcFilterTest : public ::testing::Test
{
    protected:
        struct bpf_object *m_obj = nullptr;
        int m_prog_fd = -1;

        virtual void
        SetUp() override {
            struct bpf_object_load_attr load_attr = {};
            struct bpf_program *prog;
            char *object_path_env = getenv(OBJECT_PATH_ENV_VAR);
            int err = 0;
            m_obj = object_path_env == NULL ?
                bpf_object__open(DEFAULT_OBJECT_PATH) :
                bpf_object__open(object_path_env);


            if (libbpf_get_error(m_obj)) {
                FAIL() <<
                    "Cannot open ELF object to test, you can pass a custom one with the "
                    << OBJECT_PATH_ENV_VAR <<" environment variable";
            }
            load_attr.obj = m_obj;

            prog = bpf_object__find_program_by_name(m_obj, CLASSIFIER_SECTION_NAME);
            ASSERT_FALSE(prog == NULL);
            bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS);

            err = bpf_object__load_xattr(&load_attr);
            if (err) {
                FAIL() << "Could not load the bpf program, please check your permissions";
                return;
            }

            m_prog_fd = bpf_program__fd(prog);
        }
        virtual void
        TearDown() override {
            bpf_object__close(m_obj);
            m_prog_fd = -1;
        }
        static void
        SetUpTestSuite() {
            struct rlimit rinf;
            rinf = {RLIM_INFINITY, RLIM_INFINITY};
            setrlimit(RLIMIT_MEMLOCK, &rinf);
        }
};

TEST_F(TcFilterTest, TestAllowArpPacket)
{ 
    struct bpf_prog_test_run_attr tattr = {};
    struct ethhdr eth {};
    eth.h_proto = __bpf_htons(ETH_P_ARP);

    struct iphdr iph {};

    struct tcphdr tcp {};

    struct packet_v4 pkt_v4 = {
        eth = eth,
        iph = iph,
        tcp = tcp,
    };

    struct __sk_buff skb = {};

    tattr.ctx_in = &skb;
    tattr.ctx_size_in = sizeof(skb);
    tattr.data_in = &pkt_v4;
    tattr.data_size_in = sizeof(pkt_v4);
    tattr.ctx_out = &skb;
    tattr.ctx_size_out = sizeof(skb);

    tattr.prog_fd = m_prog_fd;
    
    ASSERT_FALSE(bpf_prog_test_run_xattr(&tattr));

    EXPECT_EQ(tattr.retval, (unsigned int)ALLOW_PACKET);
}

TEST_F(TcFilterTest, TestDropUnsupportedPackets)
{ 
    struct bpf_prog_test_run_attr tattr = {};
    struct ethhdr eth {};
    eth.h_proto = __bpf_htons(ETH_P_LOOP);

    struct iphdr iph {};

    struct tcphdr tcp {};

    struct packet_v4 pkt_v4 = {
        eth = eth,
        iph = iph,
        tcp = tcp,
    };

    struct __sk_buff skb = {};

    tattr.ctx_in = &skb;
    tattr.ctx_size_in = sizeof(skb);
    tattr.data_in = &pkt_v4;
    tattr.data_size_in = sizeof(pkt_v4);
    tattr.ctx_out = &skb;
    tattr.ctx_size_out = sizeof(skb);

    tattr.prog_fd = m_prog_fd;
    
    ASSERT_FALSE(bpf_prog_test_run_xattr(&tattr));

    EXPECT_EQ(tattr.retval, (unsigned int)DROP_PACKET);
}

TEST_F(TcFilterTest, TestDropIPV6Packets)
{ 
    struct bpf_prog_test_run_attr tattr = {};
    struct ethhdr eth {};
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct ipv6hdr iph {};
    iph.version = 6;

    struct tcphdr tcp {};

    struct packet_v6 pkt_v6 = {
        eth = eth,
        iph = iph,
        tcp = tcp,
    };

    struct __sk_buff skb = {};

    tattr.ctx_in = &skb;
    tattr.ctx_size_in = sizeof(skb);
    tattr.data_in = &pkt_v6;
    tattr.data_size_in = sizeof(pkt_v6);
    tattr.ctx_out = &skb;
    tattr.ctx_size_out = sizeof(skb);

    tattr.prog_fd = m_prog_fd;
    
    ASSERT_FALSE(bpf_prog_test_run_xattr(&tattr));

    EXPECT_EQ(tattr.retval, (unsigned int)DROP_PACKET);
}

TEST_F(TcFilterTest, TestDropInvalidHeaderLength)
{
    unsigned int retval;
    struct ethhdr eth {};
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {};
    iph.version = 4;
    iph.ihl = 10;

    struct tcphdr tcp {};

    struct packet_v4 pkt_v4 = {
        eth = eth,
        iph = iph,
        tcp = tcp,
    };

    ASSERT_FALSE(bpf_prog_test_run(m_prog_fd, 1, &pkt_v4, sizeof(pkt_v4), NULL, NULL, &retval, NULL));

    EXPECT_EQ(retval, (unsigned int)DROP_PACKET);
}


TEST_F(TcFilterTest, TestDropFragmentedPacket)
{
    unsigned int retval;
    struct ethhdr eth {};
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {};
    iph.version = 4;
    iph.ihl = 5;
    iph.frag_off |= PCKT_FRAGMENTED;

    struct tcphdr tcp {};

    struct packet_v4 pkt_v4 = {
        eth = eth,
        iph = iph,
        tcp = tcp,
    };

    ASSERT_FALSE(bpf_prog_test_run(m_prog_fd, 1, &pkt_v4, sizeof(pkt_v4), NULL, NULL, &retval, NULL));

    EXPECT_EQ(retval, (unsigned int)DROP_PACKET);
}

TEST_F(TcFilterTest, TestAllowUDPPacketDNSPortSource)
{
    unsigned int retval;
    struct ethhdr eth {};
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {};
    iph.version = 4;
    iph.ihl = 5;
    iph.protocol = IPPROTO_UDP;

    struct udphdr udp {};
    udp.source = __bpf_htons(53);

    struct packet_v4_udp pkt_v4 = {
        eth = eth,
        iph = iph,
        udp = udp,
    };

    ASSERT_FALSE(bpf_prog_test_run(m_prog_fd, 1, &pkt_v4, sizeof(pkt_v4), NULL, NULL, &retval, NULL));

    EXPECT_EQ(retval, (unsigned int)ALLOW_PACKET);
}

TEST_F(TcFilterTest, TestAllowUDPPacketDNSPortDest)
{
    unsigned int retval;
    struct ethhdr eth {};
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {};
    iph.version = 4;
    iph.ihl = 5;
    iph.protocol = IPPROTO_UDP;

    struct udphdr udp {};
    udp.dest = __bpf_htons(53);

    struct packet_v4_udp pkt_v4 = {
        eth = eth,
        iph = iph,
        udp = udp,
    };

    ASSERT_FALSE(bpf_prog_test_run(m_prog_fd, 1, &pkt_v4, sizeof(pkt_v4), NULL, NULL, &retval, NULL));

    EXPECT_EQ(retval, (unsigned int)ALLOW_PACKET);
}

TEST_F(TcFilterTest, TestAllowUDPPacketDHCPClient)
{
    unsigned int retval;
    struct ethhdr eth {};
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {};
    iph.version = 4;
    iph.ihl = 5;
    iph.protocol = IPPROTO_UDP;

    struct udphdr udp {};
    udp.source = __bpf_htons(DHCP_SERVER_PORT);
    udp.dest = __bpf_htons(DHCP_CLIENT_PORT);

    struct packet_v4_udp pkt_v4 = {
        eth = eth,
        iph = iph,
        udp = udp,
    };

    ASSERT_FALSE(bpf_prog_test_run(m_prog_fd, 1, &pkt_v4, sizeof(pkt_v4), NULL, NULL, &retval, NULL));

    EXPECT_EQ(retval, (unsigned int)ALLOW_PACKET);
}

TEST_F(TcFilterTest, TestAllowUDPPacketDHCPServer)
{
    unsigned int retval;
    struct ethhdr eth {};
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {};
    iph.version = 4;
    iph.ihl = 5;
    iph.protocol = IPPROTO_UDP;

    struct udphdr udp {};
    udp.source = __bpf_htons(DHCP_CLIENT_PORT);
    udp.dest = __bpf_htons(DHCP_SERVER_PORT);

    struct packet_v4_udp pkt_v4 = {
        eth = eth,
        iph = iph,
        udp = udp,
    };

    ASSERT_FALSE(bpf_prog_test_run(m_prog_fd, 1, &pkt_v4, sizeof(pkt_v4), NULL, NULL, &retval, NULL));

    EXPECT_EQ(retval, (unsigned int)ALLOW_PACKET);
}

TEST_F(TcFilterTest, TestDropUnkownUDPPackets)
{
    unsigned int retval;
    struct ethhdr eth {};
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {};
    iph.version = 4;
    iph.ihl = 5;
    iph.protocol = IPPROTO_UDP;

    struct udphdr udp {};

    struct packet_v4_udp pkt_v4 = {
        eth = eth,
        iph = iph,
        udp = udp,
    };

    ASSERT_FALSE(bpf_prog_test_run(m_prog_fd, 1, &pkt_v4, sizeof(pkt_v4), NULL, NULL, &retval, NULL));

    EXPECT_EQ(retval, (unsigned int)DROP_PACKET);
}

TEST_F(TcFilterTest, TestDropUnkownTCPDestination)
{
    unsigned int retval;
    struct ethhdr eth {};
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {};
    iph.version = 4;
    iph.ihl = 5;
    iph.protocol = IPPROTO_TCP;

    struct tcphdr tcp {};

    struct packet_v4 pkt_v4 = {
        eth = eth,
        iph = iph,
        tcp = tcp,
    };

    ASSERT_FALSE(bpf_prog_test_run(m_prog_fd, 1, &pkt_v4, sizeof(pkt_v4), NULL, NULL, &retval, NULL));

    EXPECT_EQ(retval, (unsigned int)DROP_PACKET);
}

TEST_F(TcFilterTest, TestAllowTCPAddressInAllowedIPs)
{
    int allowed_ips_map_fd;
    unsigned int retval;
    struct ethhdr eth {};
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {};
    iph.version = 4;
    iph.ihl = 5;
    iph.protocol = IPPROTO_TCP;
    iph.daddr = __bpf_htonl(0x0A010203); // 10.1.2.3

    allowed_ips_map_fd = bpf_object__find_map_fd_by_name(m_obj, "allowed_IPs");

    int val = 1;
    int ret = bpf_map_update_elem(allowed_ips_map_fd, &iph.daddr, &val, BPF_ANY);
    ASSERT_EQ(ret, 0);

    struct tcphdr tcp {};

    struct packet_v4 pkt_v4 = {
        eth = eth,
        iph = iph,
        tcp = tcp,
    };

    ASSERT_FALSE(bpf_prog_test_run(m_prog_fd, 1, &pkt_v4, sizeof(pkt_v4), NULL, NULL, &retval, NULL));

    EXPECT_EQ(retval, (unsigned int)ALLOW_PACKET);
}

TEST_F(TcFilterTest, TestDropUnkownICMPDestination)
{
    unsigned int retval;
    struct ethhdr eth {};
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {};
    iph.version = 4;
    iph.ihl = 5;
    iph.protocol = IPPROTO_ICMP;

    struct tcphdr tcp {};

    struct packet_v4 pkt_v4 = {
        eth = eth,
        iph = iph,
        tcp = tcp,
    };

    ASSERT_FALSE(bpf_prog_test_run(m_prog_fd, 1, &pkt_v4, sizeof(pkt_v4), NULL, NULL, &retval, NULL));

    EXPECT_EQ(retval, (unsigned int)DROP_PACKET);
}

TEST_F(TcFilterTest, TestAllowICMPAddressInAllowedIPs)
{
    int allowed_ips_map_fd;
    unsigned int retval;
    struct ethhdr eth {};
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {};
    iph.version = 4;
    iph.ihl = 5;
    iph.protocol = IPPROTO_ICMP;
    iph.daddr = __bpf_htonl(0x0A010203); // 10.1.2.3

    allowed_ips_map_fd = bpf_object__find_map_fd_by_name(m_obj, "allowed_IPs");

    int val = 1;
    int ret = bpf_map_update_elem(allowed_ips_map_fd, &iph.daddr, &val, BPF_ANY);
    ASSERT_EQ(ret, 0);

    struct tcphdr tcp {};

    struct packet_v4 pkt_v4 = {
        eth = eth,
        iph = iph,
        tcp = tcp,
    };

    ASSERT_FALSE(bpf_prog_test_run(m_prog_fd, 1, &pkt_v4, sizeof(pkt_v4), NULL, NULL, &retval, NULL));

    EXPECT_EQ(retval, (unsigned int)ALLOW_PACKET);
}
