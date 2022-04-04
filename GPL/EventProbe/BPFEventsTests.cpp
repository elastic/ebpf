// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#include <sys/resource.h>
#include <gtest/gtest.h>

#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#include "EventProbe.skel.h"

class BPFFileEventsTests : public ::testing::Test
{
protected:
    struct EventProbe_bpf *m_skel;

    virtual void
    SetUp() override
    {
        m_skel = EventProbe_bpf__open_and_load();
        if (!m_skel)
        {
            FAIL() << "Failed to open and load BPF program";
        }
    }

    virtual void
    TearDown() override
    {
        EventProbe_bpf__destroy(m_skel);
    }

    static void
    SetUpTestSuite()
    {
        struct rlimit rinf;
        rinf = {RLIM_INFINITY, RLIM_INFINITY};
        if (setrlimit(RLIMIT_MEMLOCK, &rinf) == -EPERM)
        {
            FAIL() << "setrlimit failed, running the BPFFileEventsTests suite requires root permissions";
        }
    }
};

TEST_F(BPFFileEventsTests, DISABLED_TestDoUnlinkAt)
{
    // tests are disabled because at the moment of writing the kernel
    // does not support BPF_PROG_TEST_RUN against fentry/fexit programs.
    // Keeping the structure around for future reference/usage.
}
