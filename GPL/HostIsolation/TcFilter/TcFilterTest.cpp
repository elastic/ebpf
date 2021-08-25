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
#include <linux/tcp.h>

#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>
#include <bpf/libbpf.h>

#include <sched.h>
#include <sys/resource.h>

#include <gtest/gtest.h>

#define MAGIC_BYTES 123
#define OBJECT_PATH_ENV_VAR "ELASTIC_EBPF_TC_FILTER_OBJ_PATH"
#define DEFAULT_OBJECT_PATH "TcFilter.bpf.o"

struct ipv4_packet {
	struct ethhdr eth;
	struct iphdr iph;
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
            m_obj = object_path_env == NULL ?
                bpf_object__open(DEFAULT_OBJECT_PATH) :
                bpf_object__open(object_path_env);
            
            ASSERT_FALSE(libbpf_get_error(m_obj));
            load_attr.obj = m_obj;

            prog = bpf_object__find_program_by_name(m_obj, "classifier");
            ASSERT_FALSE(prog == NULL);
            bpf_program__set_type(prog, BPF_PROG_TYPE_SCHED_CLS);

            if (bpf_object__load_xattr(&load_attr)) {
                bpf_object__close(m_obj);
                FAIL();
            }

            m_prog_fd = bpf_program__fd(prog);
        }
        virtual void
        TearDown() override {
            bpf_object__close(m_obj);
        }
        static void
        SetUpTestSuite() {
            struct rlimit rinf;
            rinf = {RLIM_INFINITY, RLIM_INFINITY};
            setrlimit(RLIMIT_MEMLOCK, &rinf);
        }
};

TEST_F(TcFilterTest, Classifier)
{ 
    struct bpf_prog_test_run_attr tattr = {};
    struct ethhdr eth {};
    eth.h_proto = __bpf_htons(ETH_P_IP);

    struct iphdr iph {};
    iph.version = 4;
    iph.ihl = 5;
    iph.protocol = IPPROTO_TCP;
    iph.tot_len = __bpf_htons(MAGIC_BYTES);

    struct tcphdr tcp {};
    tcp.urg_ptr = 123;
    tcp.doff = 5;

    struct ipv4_packet pkt_v4 = {
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

    EXPECT_EQ(tattr.retval, (unsigned int)2);
}
