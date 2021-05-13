/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License 2.0;
 * you may not use this file except in compliance with the Elastic License 2.0.
 */


#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <netinet/in.h>

/* maximum netlink message size */
#define MAX_MSG 16384

struct rtnetlink_handle
{
    int                 fd;
    struct sockaddr_nl  local;
    struct sockaddr_nl  peer;
    __u32               seq;
    __u32               dump;
    int                 proto;
    FILE               *dump_fp;
#define RTNL_HANDLE_F_LISTEN_ALL_NSID       0x01
#define RTNL_HANDLE_F_SUPPRESS_NLERR        0x02
#define RTNL_HANDLE_F_STRICT_CHK        0x04
    int                 flags;
};

struct netlink_msg {
    struct nlmsghdr n;
    struct tcmsg    t;
    char            buf[MAX_MSG];
};

struct netlink_ctx {
    struct rtattr           *tail;
    struct rtnetlink_handle filter_rth;
    struct netlink_msg      msg;
};

int 
netlink_qdisc_add(const char *ifname);

int
netlink_qdisc_del(const char *ifname);

int 
netlink_filter_add_begin(struct netlink_ctx *ctx,
                         const char *ifname);

int 
netlink_filter_add_end(int fd,
                       struct netlink_ctx *ctx,
                       const char *ebpf_obj_filename);



