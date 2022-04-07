// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

// Host Isolation - this eBPF program hooks into tcp_v4_connect kprobe and adds
// entries to the IP allowlist if an allowed process tries to initiate a
// connection.

// flag needed to pick the right PT_REGS macros in bpf_tracing.h
#define __KERNEL__

#include "Kerneldefs.h"

#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

// taken from libbpf uapi include dir
#include <linux/bpf.h>

// not to be defined in production builds
//#define DEBUG_TRACE_PRINTK

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 512);
} allowed_IPs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
    __uint(max_entries, 128);
} allowed_pids SEC(".maps");

static __always_inline void add_IP_to_allowlist(__u32 daddr)
{
    // add new entry
    u32 val = 1;
    long rv = bpf_map_update_elem(&allowed_IPs, &daddr, &val, BPF_ANY);
#ifdef DEBUG_TRACE_PRINTK
    if (rv) {
        bpf_printk("Error updating hashmap\n");
    }
#endif
}

static __always_inline int enter_tcp_connect(struct sockaddr *uaddr)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 tgid     = pid_tgid >> 32;
    __u32 *elem    = NULL;
    __u32 daddr    = 0;

    struct sockaddr_in *sin = (struct sockaddr_in *)uaddr;
    bpf_probe_read(&daddr, sizeof(daddr), &sin->sin_addr.s_addr);

    // check if tgid (userspace PID) is allowed
    elem = bpf_map_lookup_elem(&allowed_pids, &tgid);

    if (elem) {
        // tgid (userspace PID) is allowed, add destination IP to IP allowlist
        add_IP_to_allowlist(daddr);
    }

    return 0;
}

// IMPORTANT:
// BPF_KPROBE uses PT_REGS_PARM2 macro underneath to get the arg
// define ARCH env var so that it gets the argument from the right register
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(tcp_v4_connect, void *sk, struct sockaddr *uaddr)
{
    return enter_tcp_connect(uaddr);
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";
