// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#include "Kerneldefs.h"
#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf.h>

#include <gtest/gtest.h>

#include <sched.h>
#include <sys/resource.h>

#include "TcFilterdefs.h"

#define OBJECT_PATH_ENV_VAR "ELASTIC_EBPF_TC_FILTER_OBJ_PATH"
#define DEFAULT_OBJECT_PATH "TcFilter.bpf.o"
#define CLASSIFIER_SECTION_NAME "classifier"

#define MAGIC_BYTES 123
#define __packed __attribute__((__packed__))

struct packet_v4 {
    struct ethhdr eth;
    struct iphdr iph;
    struct tcphdr tcp;
} __packed;

struct packet_v4_udp {
    struct ethhdr eth;
    struct iphdr iph;
    struct udphdr udp;
} __packed;

struct packet_v6 {
    struct ethhdr eth;
    struct ipv6hdr iph;
    struct tcphdr tcp;
} __packed;

class BPFTcFilterTests : public ::testing::Test
{
  protected:
    struct bpf_object *m_obj = nullptr;
    int m_prog_fd            = -1;

    virtual void SetUp() override
    {
        struct bpf_program *prog = nullptr;
        char *object_path_env    = getenv(OBJECT_PATH_ENV_VAR);
        int err                  = 0;
        m_obj                    = object_path_env == NULL ? bpf_object__open(DEFAULT_OBJECT_PATH)
                                                           : bpf_object__open(object_path_env);

        if (libbpf_get_error(m_obj)) {
            FAIL() << "Cannot open ELF object to test, you can pass a custom one with the "
                   << OBJECT_PATH_ENV_VAR << " environment variable";
        }

        prog = bpf_object__find_program_by_name(m_obj, CLASSIFIER_SECTION_NAME);
        ASSERT_FALSE(prog == NULL);

        bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS);

        err = bpf_object__load(m_obj);
        if (err) {
            FAIL() << "Could not load the bpf program, please check your permissions";
            return;
        }

        m_prog_fd = bpf_program__fd(prog);
    }

    virtual void TearDown() override
    {
        int err                         = 0;
        struct bpf_map *allowed_ips_map = bpf_object__find_map_by_name(m_obj, "allowed_IPs");
        if (!allowed_ips_map) {
            FAIL() << "Could not find the allowed_IPs map";
            return;
        }
        err = bpf_map__unpin(allowed_ips_map, bpf_map__get_pin_path(allowed_ips_map));
        if (err != 0) {
            FAIL() << "Could not unpin the allowed_IPs map";
            return;
        }

        struct bpf_map *allowed_subnets_map =
            bpf_object__find_map_by_name(m_obj, "allowed_subnets");
        if (!allowed_subnets_map) {
            FAIL() << "Could not find the allowed_subnets map";
            return;
        }
        err = bpf_map__unpin(allowed_subnets_map, bpf_map__get_pin_path(allowed_subnets_map));
        if (err != 0) {
            FAIL() << "Could not unpin the allowed_subnets map";
            return;
        }

        bpf_object__close(m_obj);
        m_prog_fd = -1;
    }

    static void SetUpTestSuite()
    {
        struct rlimit rinf;
        rinf = {RLIM_INFINITY, RLIM_INFINITY};
        if (setrlimit(RLIMIT_MEMLOCK, &rinf) == -EPERM) {
            FAIL()
                << "setrlimit failed, running the BPFTcFilterTests suite requires root permissions";
        }
    }
};

TEST_F(BPFTcFilterTests, TestAllowArpPacket)
{
    struct bpf_test_run_opts opts = {};
    opts.sz                       = sizeof(opts);
    struct ethhdr eth {
    };
    eth.h_proto = __bpf_htons(ETH_P_ARP);

    struct iphdr iph {
    };

    struct tcphdr tcp {
    };

    struct packet_v4 pkt_v4 {
    };
    pkt_v4.eth = eth;
    pkt_v4.iph = iph;
    pkt_v4.tcp = tcp;

    struct __sk_buff skb = {};

    opts.ctx_in       = &skb;
    opts.ctx_size_in  = sizeof(skb);
    opts.data_in      = &pkt_v4;
    opts.data_size_in = sizeof(pkt_v4);
    opts.ctx_out      = &skb;
    opts.ctx_size_out = sizeof(skb);

    int err = bpf_prog_test_run_opts(m_prog_fd, &opts);

    EXPECT_EQ(err, 0);
    EXPECT_EQ(opts.retval, (unsigned int)ALLOW_PACKET);
}

TEST_F(BPFTcFilterTests, TestDropUnsupportedPackets)
{
    struct bpf_test_run_opts opts = {};
    opts.sz                       = sizeof(opts);
    struct ethhdr eth {
    };
    eth.h_proto = __bpf_htons(ETH_P_LOOP);

    struct iphdr iph {
    };

    struct tcphdr tcp {
    };

    struct packet_v4 pkt_v4 {
    };
    pkt_v4.eth = eth;
    pkt_v4.iph = iph;
    pkt_v4.tcp = tcp;

    struct __sk_buff skb = {};

    opts.ctx_in       = &skb;
    opts.ctx_size_in  = sizeof(skb);
    opts.data_in      = &pkt_v4;
    opts.data_size_in = sizeof(pkt_v4);
    opts.ctx_out      = &skb;
    opts.ctx_size_out = sizeof(skb);

    int err = bpf_prog_test_run_opts(m_prog_fd, &opts);

    EXPECT_EQ(err, 0);
    EXPECT_EQ(opts.retval, (unsigned int)DROP_PACKET);
}

TEST_F(BPFTcFilterTests, TestDropIPV6Packets)
{
    struct bpf_test_run_opts opts = {};
    opts.sz                       = sizeof(opts);
    struct ethhdr eth {
    };
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct ipv6hdr iph {
    };
    iph.version = 6;

    struct tcphdr tcp {
    };

    struct packet_v6 pkt_v6 {
    };
    pkt_v6.eth = eth;
    pkt_v6.iph = iph;
    pkt_v6.tcp = tcp;

    struct __sk_buff skb = {};

    opts.ctx_in       = &skb;
    opts.ctx_size_in  = sizeof(skb);
    opts.data_in      = &pkt_v6;
    opts.data_size_in = sizeof(pkt_v6);
    opts.ctx_out      = &skb;
    opts.ctx_size_out = sizeof(skb);

    int err = bpf_prog_test_run_opts(m_prog_fd, &opts);

    EXPECT_EQ(err, 0);
    EXPECT_EQ(opts.retval, (unsigned int)DROP_PACKET);
}

TEST_F(BPFTcFilterTests, TestDropInvalidHeaderLength)
{
    struct bpf_test_run_opts opts = {};
    opts.sz                       = sizeof(opts);
    struct ethhdr eth {
    };
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {
    };
    iph.version = 4;
    iph.ihl     = 10;

    struct tcphdr tcp {
    };

    struct packet_v4 pkt_v4 {
    };
    pkt_v4.eth = eth;
    pkt_v4.iph = iph;
    pkt_v4.tcp = tcp;

    opts.data_in      = &pkt_v4;
    opts.data_size_in = sizeof(pkt_v4);

    int err = bpf_prog_test_run_opts(m_prog_fd, &opts);

    EXPECT_EQ(err, 0);
    EXPECT_EQ(opts.retval, (unsigned int)DROP_PACKET);
}

TEST_F(BPFTcFilterTests, TestDropFragmentedPacket)
{
    struct bpf_test_run_opts opts = {};
    opts.sz                       = sizeof(opts);
    struct ethhdr eth {
    };
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {
    };
    iph.version = 4;
    iph.ihl     = 5;
    iph.frag_off |= PCKT_FRAGMENTED;

    struct tcphdr tcp {
    };

    struct packet_v4 pkt_v4 {
    };
    pkt_v4.eth = eth;
    pkt_v4.iph = iph;
    pkt_v4.tcp = tcp;

    opts.data_in      = &pkt_v4;
    opts.data_size_in = sizeof(pkt_v4);

    int err = bpf_prog_test_run_opts(m_prog_fd, &opts);

    EXPECT_EQ(err, 0);
    EXPECT_EQ(opts.retval, (unsigned int)DROP_PACKET);
}

TEST_F(BPFTcFilterTests, TestAllowUDPPacketDNSPortSource)
{
    struct bpf_test_run_opts opts = {};
    opts.sz                       = sizeof(opts);
    struct ethhdr eth {
    };
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {
    };
    iph.version  = 4;
    iph.ihl      = 5;
    iph.protocol = IPPROTO_UDP;

    struct udphdr udp {
    };
    udp.source = __bpf_htons(53);

    struct packet_v4_udp pkt_v4 {
    };
    pkt_v4.eth = eth;
    pkt_v4.iph = iph;
    pkt_v4.udp = udp;

    opts.data_in      = &pkt_v4;
    opts.data_size_in = sizeof(pkt_v4);

    int err = bpf_prog_test_run_opts(m_prog_fd, &opts);

    EXPECT_EQ(err, 0);
    EXPECT_EQ(opts.retval, (unsigned int)ALLOW_PACKET);
}

TEST_F(BPFTcFilterTests, TestAllowUDPPacketDNSPortDest)
{
    struct bpf_test_run_opts opts = {};
    opts.sz                       = sizeof(opts);
    struct ethhdr eth {
    };
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {
    };
    iph.version  = 4;
    iph.ihl      = 5;
    iph.protocol = IPPROTO_UDP;

    struct udphdr udp {
    };
    udp.dest = __bpf_htons(53);

    struct packet_v4_udp pkt_v4 {
    };
    pkt_v4.eth = eth;
    pkt_v4.iph = iph;
    pkt_v4.udp = udp;

    opts.data_in      = &pkt_v4;
    opts.data_size_in = sizeof(pkt_v4);

    int err = bpf_prog_test_run_opts(m_prog_fd, &opts);

    EXPECT_EQ(err, 0);
    EXPECT_EQ(opts.retval, (unsigned int)ALLOW_PACKET);
}

TEST_F(BPFTcFilterTests, TestAllowUDPPacketDHCPClient)
{
    struct bpf_test_run_opts opts = {};
    opts.sz                       = sizeof(opts);
    struct ethhdr eth {
    };
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {
    };
    iph.version  = 4;
    iph.ihl      = 5;
    iph.protocol = IPPROTO_UDP;

    struct udphdr udp {
    };
    udp.source = __bpf_htons(DHCP_SERVER_PORT);
    udp.dest   = __bpf_htons(DHCP_CLIENT_PORT);

    struct packet_v4_udp pkt_v4 {
    };
    pkt_v4.eth = eth;
    pkt_v4.iph = iph;
    pkt_v4.udp = udp;

    opts.data_in      = &pkt_v4;
    opts.data_size_in = sizeof(pkt_v4);

    int err = bpf_prog_test_run_opts(m_prog_fd, &opts);

    EXPECT_EQ(err, 0);
    EXPECT_EQ(opts.retval, (unsigned int)ALLOW_PACKET);
}

TEST_F(BPFTcFilterTests, TestAllowUDPPacketDHCPServer)
{
    struct bpf_test_run_opts opts = {};
    opts.sz                       = sizeof(opts);
    struct ethhdr eth {
    };
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {
    };
    iph.version  = 4;
    iph.ihl      = 5;
    iph.protocol = IPPROTO_UDP;

    struct udphdr udp {
    };
    udp.source = __bpf_htons(DHCP_CLIENT_PORT);
    udp.dest   = __bpf_htons(DHCP_SERVER_PORT);

    struct packet_v4_udp pkt_v4 {
    };
    pkt_v4.eth = eth;
    pkt_v4.iph = iph;
    pkt_v4.udp = udp;

    opts.data_in      = &pkt_v4;
    opts.data_size_in = sizeof(pkt_v4);

    int err = bpf_prog_test_run_opts(m_prog_fd, &opts);

    EXPECT_EQ(err, 0);
    EXPECT_EQ(opts.retval, (unsigned int)ALLOW_PACKET);
}

TEST_F(BPFTcFilterTests, TestDropUnknownUDPPackets)
{
    struct bpf_test_run_opts opts = {};
    opts.sz                       = sizeof(opts);
    struct ethhdr eth {
    };
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {
    };
    iph.version  = 4;
    iph.ihl      = 5;
    iph.protocol = IPPROTO_UDP;

    struct udphdr udp {
    };

    struct packet_v4_udp pkt_v4 {
    };
    pkt_v4.eth = eth;
    pkt_v4.iph = iph;
    pkt_v4.udp = udp;

    opts.data_in      = &pkt_v4;
    opts.data_size_in = sizeof(pkt_v4);

    int err = bpf_prog_test_run_opts(m_prog_fd, &opts);

    EXPECT_EQ(err, 0);
    EXPECT_EQ(opts.retval, (unsigned int)DROP_PACKET);
}

TEST_F(BPFTcFilterTests, TestDropUnknownTCPDestination)
{
    struct bpf_test_run_opts opts = {};
    opts.sz                       = sizeof(opts);
    struct ethhdr eth {
    };
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {
    };
    iph.version  = 4;
    iph.ihl      = 5;
    iph.protocol = IPPROTO_TCP;

    struct tcphdr tcp {
    };

    struct packet_v4 pkt_v4 {
    };
    pkt_v4.eth = eth;
    pkt_v4.iph = iph;
    pkt_v4.tcp = tcp;

    opts.data_in      = &pkt_v4;
    opts.data_size_in = sizeof(pkt_v4);

    int err = bpf_prog_test_run_opts(m_prog_fd, &opts);

    EXPECT_EQ(err, 0);
    EXPECT_EQ(opts.retval, (unsigned int)DROP_PACKET);
}

TEST_F(BPFTcFilterTests, TestAllowTCPAddressInAllowedIPs)
{
    int allowed_ips_map_fd;
    struct bpf_test_run_opts opts = {};
    opts.sz                       = sizeof(opts);
    struct ethhdr eth {
    };
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {
    };
    iph.version  = 4;
    iph.ihl      = 5;
    iph.protocol = IPPROTO_TCP;
    iph.daddr    = __bpf_htonl(0x0A010203); // 10.1.2.3

    allowed_ips_map_fd = bpf_object__find_map_fd_by_name(m_obj, "allowed_IPs");

    int val = 1;
    int ret = bpf_map_update_elem(allowed_ips_map_fd, &iph.daddr, &val, BPF_ANY);
    ASSERT_EQ(ret, 0);

    struct tcphdr tcp {
    };

    struct packet_v4 pkt_v4 {
    };
    pkt_v4.eth = eth;
    pkt_v4.iph = iph;
    pkt_v4.tcp = tcp;

    opts.data_in      = &pkt_v4;
    opts.data_size_in = sizeof(pkt_v4);

    int err = bpf_prog_test_run_opts(m_prog_fd, &opts);

    EXPECT_EQ(err, 0);
    EXPECT_EQ(opts.retval, (unsigned int)ALLOW_PACKET);
}

TEST_F(BPFTcFilterTests, TestDropUnknownICMPDestination)
{
    struct bpf_test_run_opts opts = {};
    opts.sz                       = sizeof(opts);
    struct ethhdr eth {
    };
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {
    };
    iph.version  = 4;
    iph.ihl      = 5;
    iph.protocol = IPPROTO_ICMP;

    struct tcphdr tcp {
    };

    struct packet_v4 pkt_v4 {
    };
    pkt_v4.eth = eth;
    pkt_v4.iph = iph;
    pkt_v4.tcp = tcp;

    opts.data_in      = &pkt_v4;
    opts.data_size_in = sizeof(pkt_v4);

    int err = bpf_prog_test_run_opts(m_prog_fd, &opts);

    EXPECT_EQ(err, 0);
    EXPECT_EQ(opts.retval, (unsigned int)DROP_PACKET);
}

TEST_F(BPFTcFilterTests, TestAllowICMPAddressInAllowedIPs)
{
    int allowed_ips_map_fd;
    struct bpf_test_run_opts opts = {};
    opts.sz                       = sizeof(opts);
    struct ethhdr eth {
    };
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {
    };
    iph.version  = 4;
    iph.ihl      = 5;
    iph.protocol = IPPROTO_ICMP;
    iph.daddr    = __bpf_htonl(0x0A010203); // 10.1.2.3

    allowed_ips_map_fd = bpf_object__find_map_fd_by_name(m_obj, "allowed_IPs");

    int val = 1;
    int ret = bpf_map_update_elem(allowed_ips_map_fd, &iph.daddr, &val, BPF_ANY);
    ASSERT_EQ(ret, 0);

    struct tcphdr tcp {
    };

    struct packet_v4 pkt_v4 {
    };
    pkt_v4.eth = eth;
    pkt_v4.iph = iph;
    pkt_v4.tcp = tcp;

    opts.data_in      = &pkt_v4;
    opts.data_size_in = sizeof(pkt_v4);

    int err = bpf_prog_test_run_opts(m_prog_fd, &opts);

    EXPECT_EQ(err, 0);
    EXPECT_EQ(opts.retval, (unsigned int)ALLOW_PACKET);
}
