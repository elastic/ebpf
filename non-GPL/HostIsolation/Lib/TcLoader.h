// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#ifndef EBPF_TCLOADER_H
#define EBPF_TCLOADER_H

#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>
#include <stdio.h>

/* maximum netlink message size */
#define MAX_MSG 16384
#define ELASTIC_TC_FILTER_MARKER "el-endpo_"

struct rtnetlink_handle {
    int fd;
    struct sockaddr_nl local;
    struct sockaddr_nl peer;
    __u32 seq;
    __u32 dump;
    int proto;
    FILE *dump_fp;
#define RTNL_HANDLE_F_LISTEN_ALL_NSID 0x01
#define RTNL_HANDLE_F_SUPPRESS_NLERR 0x02
#define RTNL_HANDLE_F_STRICT_CHK 0x04
    int flags;
};

struct netlink_msg {
    struct nlmsghdr n;
    struct tcmsg t;
    char buf[MAX_MSG];
};

struct netlink_ctx {
    struct rtattr *tail;
    struct rtnetlink_handle filter_rth;
    struct netlink_msg msg;
};

/**
 * @brief Add qdisc to a network interface
 *
 * @param[in] ifname Network interface name
 * @return 0 on success, -EBUSY if a non-clsact qdisc occupies the
 * ingress/clsact slot, or another negative error value on failure
 */
int netlink_qdisc_add(const char *ifname);

/**
 * @brief Remove qdisc from a network interface
 *
 * @param[in] ifname Network interface name
 * @return Error value (0 for success)
 */
int netlink_qdisc_del(const char *ifname);

/**
 * @brief Add eBPF tc filter to a network interface (initialize only)
 *
 * @param[in] ctx Context containing netlink state - allocated and passed by
 * caller
 * @param[in] ifname Network interface name
 * @return Error value (0 for success)
 */
int netlink_filter_add_begin(struct netlink_ctx *ctx, const char *ifname);

/**
 * @brief Add eBPF tc filter to a network interface (commit)
 *
 * @param[in] fd eBPF program file descriptor
 * @param[in] ctx Context containing netlink state (from previous add_begin()
 * call) - passed by caller
 * @return Error value (0 for success)
 */
int netlink_filter_add_end(int fd, struct netlink_ctx *ctx);

/**
 * @brief Check if an interface has our eBPF tc filter attached
 *
 * @param[in] ifname Network interface name
 * @param[in] marker_name Prefix to match against TCA_BPF_NAME
 * @return 1 if found, 0 if not found, -1 on error
 */
int netlink_filter_exists(const char *ifname, const char *marker_name);

/**
 * @brief Delete our eBPF tc filter from a network interface
 *
 * @param[in] ifname Network interface name
 * @param[in] marker_name Prefix to match against TCA_BPF_NAME
 * @return 0 on success, -1 on error
 */
int netlink_filter_del(const char *ifname, const char *marker_name);
#endif
