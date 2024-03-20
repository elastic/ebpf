// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

//
// Loader for tc eBPF programs
//
#include "TcLoader.h"

#include "Common.h"
#include <argp.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* linux definitions */
#define SOL_NETLINK 270
#define NETLINK_EXT_ACK 11

#define ETH_P_ALL 0x0003 /* Every packet */

#define TC_H_MAJ_MASK (0xFFFF0000U)
#define TC_H_MIN_MASK (0x0000FFFFU)
#define TC_H_MAJ(h) ((h)&TC_H_MAJ_MASK)
#define TC_H_MIN(h) ((h)&TC_H_MIN_MASK)
#define TC_H_MAKE(maj, min) (((maj)&TC_H_MAJ_MASK) | ((min)&TC_H_MIN_MASK))
#define TC_H_INGRESS (0xFFFFFFF1U)
#define TC_H_CLSACT TC_H_INGRESS
#define TC_H_MIN_EGRESS 0xFFF3U
#define TCA_BPF_FLAG_ACT_DIRECT (1 << 0)

enum {
    TCA_BPF_UNSPEC,
    TCA_BPF_ACT,
    TCA_BPF_POLICE,
    TCA_BPF_CLASSID,
    TCA_BPF_OPS_LEN,
    TCA_BPF_OPS,
    TCA_BPF_FD,
    TCA_BPF_NAME,
    TCA_BPF_FLAGS,
    TCA_BPF_FLAGS_GEN,
    TCA_BPF_TAG,
    TCA_BPF_ID,
    __TCA_BPF_MAX,
};

#define NLMSG_TAIL(nmsg) ((struct rtattr *)(((void *)(nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

static int attr_put(struct nlmsghdr *n, int max, int type, const void *buf, int attr_len)
{
    int len            = RTA_LENGTH(attr_len);
    struct rtattr *rta = NULL;
    int rv             = -1;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > max) {
        ebpf_log("attr_put error: message longer than %d\n", max);
        rv = -1;
        goto out;
    }

    rta           = NLMSG_TAIL(n);
    rta->rta_len  = len;
    rta->rta_type = type;

    if (attr_len) {
        memcpy(RTA_DATA(rta), buf, attr_len);
    }

    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    rv           = 0;
out:
    return rv;
}

static int attr_put_32(struct nlmsghdr *n, int max, int type, __u32 data)
{
    return attr_put(n, max, type, &data, sizeof(__u32));
}

static int attr_put_str(struct nlmsghdr *n, int max, int type, const char *s)
{
    return attr_put(n, max, type, s, strlen(s) + 1);
}

static void rtnetlink_close(struct rtnetlink_handle *r)
{
    if (r->fd >= 0) {
        close(r->fd);
        r->fd = -1;
    }
}

static void rtnetlink_send_error(struct nlmsgerr *err)
{
    ebpf_log("rtnetlink replied: %s\n", strerror(-err->error));
}

static int rtnetlink_open(struct rtnetlink_handle *rth)
{
    socklen_t address_len = 0;
    int sendbuf           = 32 * 1024;
    int receivebuf        = 1024 * 1024;
    int one               = 1;
    int rv                = -1;

    if (rth == NULL) {
        ebpf_log("error: rth is NULL\n");
        rv = -1;
        goto out;
    }

    memset(rth, 0, sizeof(*rth));

    rth->proto = NETLINK_ROUTE;
    rth->fd    = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (rth->fd < 0) {
        ebpf_log("cannot open netlink socket\n");
        rv = -1;
        goto out;
    }

    if (setsockopt(rth->fd, SOL_SOCKET, SO_SNDBUF, &sendbuf, sizeof(sendbuf)) < 0) {
        ebpf_log("error setsockopt sendbuf\n");
        rv = -1;
        goto out;
    }

    if (setsockopt(rth->fd, SOL_SOCKET, SO_RCVBUF, &receivebuf, sizeof(receivebuf)) < 0) {
        ebpf_log("error setsockopt receivebuf\n");
        rv = -1;
        goto out;
    }

    if (setsockopt(rth->fd, SOL_NETLINK, NETLINK_EXT_ACK, &one, sizeof(one))) {
        ebpf_log("error setsockopt netlink\n");
        rv = -1;
        goto out;
    }

    memset(&rth->local, 0, sizeof(rth->local));

    rth->local.nl_family = AF_NETLINK;
    rth->local.nl_groups = 0;

    if (bind(rth->fd, (struct sockaddr *)&rth->local, sizeof(rth->local)) < 0) {
        ebpf_log("failed to bind netlink socket\n");
        rv = -1;
        goto out;
    }
    address_len = sizeof(rth->local);
    if (getsockname(rth->fd, (struct sockaddr *)&rth->local, &address_len) < 0) {
        ebpf_log("error getsockname\n");
        rv = -1;
        goto out;
    }
    if (address_len != sizeof(rth->local)) {
        ebpf_log("bad address length %d\n", address_len);
        rv = -1;
        goto out;
    }
    if (rth->local.nl_family != AF_NETLINK) {
        ebpf_log("bad address family %d\n", rth->local.nl_family);
        rv = -1;
        goto out;
    }

    rth->seq = time(NULL);
    rv       = 0;
out:
    return rv;
}

static int rtnetlink_recv(int fd, struct msghdr *msg, char **answer)
{
    struct iovec *iov = NULL;
    char *buf         = NULL;
    int len           = 0;
    int rv            = 0;

    if (!msg) {
        ebpf_log("rtnetlink_recv error: NULL parameter\n");
        rv = -1;
        goto out;
    }

    iov           = msg->msg_iov;
    iov->iov_base = NULL;
    iov->iov_len  = 0;

    do {
        len = recvmsg(fd, msg, MSG_PEEK | MSG_TRUNC);
    } while (len < 0 && (errno == EINTR || errno == EAGAIN));

    if (len <= 0) {
        ebpf_log("netlink recv error \n");
        rv = len;
        goto out;
    }

    if (len < 32768) {
        len = 32768;
    }

    buf = malloc(len);
    if (!buf) {
        ebpf_log("malloc error \n");
        rv = -ENOMEM;
        goto out;
    }

    iov->iov_base = buf;
    iov->iov_len  = len;

    do {
        len = recvmsg(fd, msg, 0);
    } while (len < 0 && (errno == EINTR || errno == EAGAIN));

    if (len <= 0) {
        free(buf);
        ebpf_log("netlink recv error \n");
        rv = len;
        goto out;
    }

    if (answer) {
        *answer = buf;
    } else {
        free(buf);
    }

    rv = len;
out:
    return rv;
}

static int rtnetlink_send(struct rtnetlink_handle *rtnl, struct nlmsghdr *nlmsg)
{
    struct iovec iov  = {.iov_base = nlmsg, .iov_len = nlmsg->nlmsg_len};
    struct iovec riov = {0};

    struct sockaddr_nl nladdr = {.nl_family = AF_NETLINK};

    struct msghdr msg = {
        .msg_name    = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov     = &iov,
        .msg_iovlen  = 1,
    };

    unsigned int seq   = 0;
    struct nlmsghdr *h = NULL;
    int recv_len       = 0;
    char *buf          = NULL;
    int rv             = -1;

    if (!rtnl || !nlmsg) {
        ebpf_log("rtnetlink_send error: NULL parameter\n");
        rv = -1;
        goto out;
    }

    h            = iov.iov_base;
    h->nlmsg_seq = seq = ++rtnl->seq;
    /* request acknowledgement (NLMSG_ERROR packet) */
    h->nlmsg_flags |= NLM_F_ACK;

    if (sendmsg(rtnl->fd, &msg, 0) < 0) {
        ebpf_log("failure talking to rtnetlink\n");
        rv = -1;
        goto out;
    }

    /* switch to response iov */
    memset(&riov, 0, sizeof(riov));
    msg.msg_iov    = &riov;
    msg.msg_iovlen = 1;

    recv_len = rtnetlink_recv(rtnl->fd, &msg, &buf);

    if (recv_len <= 0) {
        rv = -1;
        goto out;
    }

    if (msg.msg_namelen != sizeof(nladdr)) {
        ebpf_log("sender addr length == %d\n", msg.msg_namelen);
        rv = -1;
        goto out;
    }

    for (h = (struct nlmsghdr *)buf; recv_len >= sizeof(*h);) {
        int len = h->nlmsg_len;
        int l   = len - sizeof(*h);

        if (l < 0 || len > recv_len) {
            if (msg.msg_flags & MSG_TRUNC) {
                ebpf_log("truncated message\n");
                rv = -1;
                goto out;
            }
            ebpf_log("bad message length: len=%d\n", len);
            rv = -1;
            goto out;
        }

        if (0 != nladdr.nl_pid || h->nlmsg_pid != rtnl->local.nl_pid || h->nlmsg_seq > seq ||
            h->nlmsg_seq < seq - 1) {
            /* skip this message. */
            recv_len -= NLMSG_ALIGN(len);
            h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
            continue;
        }

        /* Parse acknowledgment packet */
        if (h->nlmsg_type == NLMSG_ERROR) {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
            int error            = err->error;

            if (l < sizeof(struct nlmsgerr)) {
                ebpf_log("error truncated\n");
                rv = -1;
                goto out;
            }

            if (error) {
                rtnetlink_send_error(err);
            }

            rv = error ? -1 : 0;
            goto out;
        }

        ebpf_log("bad netlink reply\n");

        recv_len -= NLMSG_ALIGN(len);
        h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
    }

    if (msg.msg_flags & MSG_TRUNC) {
        ebpf_log("message truncated\n");
        rv = -1;
        goto out;
    }

    if (recv_len) {
        ebpf_log("uneven reply, remained: %d\n", recv_len);
        rv = -1;
        goto out;
    }

out:
    if (buf) {
        free(buf);
    }
    return rv;
}

static int netlink_qdisc(int cmd, unsigned int flags, const char *ifname)
{
    int rv                            = -1;
    struct rtnetlink_handle qdisc_rth = {.fd = -1};
    struct netlink_msg qdisc_req      = {
             .n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct tcmsg)),
             .n.nlmsg_flags = NLM_F_REQUEST | flags,
             .n.nlmsg_type  = cmd,
             .t.tcm_family  = AF_UNSPEC,
    };

    if (!ifname) {
        ebpf_log("netlink_qdisc error: NULL parameter\n");
        rv = -1;
        goto out;
    }

    if (rtnetlink_open(&qdisc_rth) < 0) {
        ebpf_log("failed to open netlink\n");
        rv = -1;
        goto out;
    }
    qdisc_req.t.tcm_parent = TC_H_CLSACT;
    qdisc_req.t.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);
    attr_put(&qdisc_req.n, sizeof(qdisc_req), TCA_KIND, "clsact", strlen("clsact") + 1);

    qdisc_req.t.tcm_ifindex = if_nametoindex(ifname);
    if (0 == qdisc_req.t.tcm_ifindex) {
        ebpf_log("failed to find device %s\n", ifname);
        rv = -1;
        goto out;
    }
    /* talk to netlink */
    if (rtnetlink_send(&qdisc_rth, &qdisc_req.n) < 0) {
        ebpf_log("error talking to the kernel (rtnetlink_send)\n");
        rv = -1;
        goto out;
    }

    rv = 0;
out:
    rtnetlink_close(&qdisc_rth);
    return rv;
}

int netlink_qdisc_add(const char *ifname)
{
    return netlink_qdisc(RTM_NEWQDISC, NLM_F_EXCL | NLM_F_CREATE, ifname);
}

int netlink_qdisc_del(const char *ifname)
{
    return netlink_qdisc(RTM_DELQDISC, 0, ifname);
}

int netlink_filter_add_begin(struct netlink_ctx *ctx, const char *ifname)
{
    int rv             = -1;
    __u32 protocol     = 0;
    struct nlmsghdr *n = NULL;

    if (!ctx) {
        ebpf_log("netlink_filter_add_begin error: NULL parameter\n");
        rv = -1;
        goto out;
    }

    /* Initialize context for filter add */
    memset(ctx, 0, sizeof(*ctx));
    ctx->filter_rth.fd     = -1;
    ctx->msg.n.nlmsg_len   = NLMSG_LENGTH(sizeof(struct tcmsg));
    ctx->msg.n.nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE;
    ctx->msg.n.nlmsg_type  = RTM_NEWTFILTER;
    ctx->msg.t.tcm_family  = AF_UNSPEC;

    if (rtnetlink_open(&ctx->filter_rth) < 0) {
        ebpf_log("failed to open netlink\n");
        rtnetlink_close(&ctx->filter_rth);
        rv = -1;
        goto out;
    }

    protocol              = htons(ETH_P_ALL);
    ctx->msg.t.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
    ctx->msg.t.tcm_info   = TC_H_MAKE(0 << 16, protocol);
    attr_put(&ctx->msg.n, sizeof(ctx->msg), TCA_KIND, "bpf", strlen("bpf") + 1);

    ctx->msg.t.tcm_ifindex = if_nametoindex(ifname);
    if (0 == ctx->msg.t.tcm_ifindex) {
        ebpf_log("failed to find device %s\n", ifname);
        rtnetlink_close(&ctx->filter_rth);
        rv = -1;
        goto out;
    }

    n         = &ctx->msg.n;
    ctx->tail = (struct rtattr *)(((void *)n) + NLMSG_ALIGN(n->nlmsg_len));
    attr_put(n, MAX_MSG, TCA_OPTIONS, NULL, 0);

    rv = 0;
out:
    return rv;
}

int netlink_filter_add_end(int fd, struct netlink_ctx *ctx, const char *ebpf_obj_filename)
{
    struct nlmsghdr *nl = NULL;
    char buf[128];
    int rv  = -1;
    int len = 0;

    if (!ctx || !ebpf_obj_filename) {
        ebpf_log("netlink_filter_add_end error: NULL parameter\n");
        rv = -1;
        goto out;
    }

    nl = &ctx->msg.n;
    memset(buf, 0, sizeof(buf));

    len = snprintf(buf, sizeof(buf), "%s:[.text]", ebpf_obj_filename);
    if (len < 0 || len >= sizeof(buf)) {
        ebpf_log("netlink_filter_add_end error: filename too long\n");
        rv = -1;
        goto out;
    }

    attr_put_32(nl, MAX_MSG, TCA_BPF_FD, fd);
    attr_put_str(nl, MAX_MSG, TCA_BPF_NAME, buf);
    attr_put_32(nl, MAX_MSG, TCA_BPF_FLAGS, TCA_BPF_FLAG_ACT_DIRECT);
    ctx->tail->rta_len = (((void *)nl) + nl->nlmsg_len) - (void *)ctx->tail;

    /* talk to netlink */
    if (rtnetlink_send(&ctx->filter_rth, &ctx->msg.n) < 0) {
        ebpf_log("error talking to the kernel (rtnetlink_send)\n");
        rv = -1;
        goto out;
    }

    rv = 0;
out:
    if (ctx) {
        rtnetlink_close(&ctx->filter_rth);
    }
    return rv;
}
