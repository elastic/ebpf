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

#include <sys/resource.h>
#include <gtest/gtest.h>

#define __aligned_u64 __u64 __attribute__((aligned(8)))
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/bpf_endian.h>

#include "Probe.skel.h"

class BPFFileEventsTests : public ::testing::Test
{
protected:
    struct Probe_bpf *m_skel;

    virtual void
    SetUp() override
    {
        m_skel = Probe_bpf__open_and_load();
        if (!m_skel)
        {
            FAIL() << "Failed to open and load BPF program";
        }
    }

    virtual void
    TearDown() override
    {
        Probe_bpf__destroy(m_skel);
    }

    static void
    SetUpTestSuite()
    {
        struct rlimit rinf;
        rinf = {RLIM_INFINITY, RLIM_INFINITY};
        if (setrlimit(RLIMIT_MEMLOCK, &rinf) == -EPERM)
        {
            FAIL() << "setrlimit failed, running the BPFTcFilterTests suite requires root permissions";
        }
    }
};

TEST_F(BPFFileEventsTests, DISABLED_TestDoUnlinkAt)
{
    // tests are disabled because at the moment of writing the kernel
    // does not support BPF_PROG_TEST_RUN against fentry/fexit programs.
    // Keeping the structure around for future reference/usage.
}
