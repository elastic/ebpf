// TODO:
// LICENSE
//
// Host Isolation standalone demo
// Loader for eBPF program #1 (replacement for 'tc filter add')
// 
#include <stdio.h>
#include <stdlib.h>
#include <argp.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>

#include <net/if.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <sys/stat.h>

/* UPDATE ACCORDINGLY */
#define IFNAME_TO_ATTACH_TO "ens33"
#define EBPF_OBJ_FILE_NAME "tc_filter.o"

/* maximum netlink message size */
#define MAX_MSG 16384

/* linux definitions */
#define SOL_NETLINK 270
#define NETLINK_EXT_ACK 11

#define ETH_P_ALL   0x0003      /* Every packet */

#define TC_H_MAJ_MASK (0xFFFF0000U)
#define TC_H_MIN_MASK (0x0000FFFFU)
#define TC_H_MAJ(h) ((h)&TC_H_MAJ_MASK)
#define TC_H_MIN(h) ((h)&TC_H_MIN_MASK)
#define TC_H_MAKE(maj,min) (((maj)&TC_H_MAJ_MASK)|((min)&TC_H_MIN_MASK))
#define TC_H_INGRESS    (0xFFFFFFF1U)
#define TC_H_CLSACT     TC_H_INGRESS
#define TC_H_MIN_EGRESS         0xFFF3U
#define TCA_BPF_FLAG_ACT_DIRECT     (1 << 0)

enum
{
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

#define NLMSG_TAIL(nmsg) \
    ((struct rtattr *) (((void *) (nmsg)) + NLMSG_ALIGN((nmsg)->nlmsg_len)))

struct rtnetlink_handle
{
    int         fd;
    struct sockaddr_nl  local;
    struct sockaddr_nl  peer;
    __u32           seq;
    __u32           dump;
    int         proto;
    FILE               *dump_fp;
#define RTNL_HANDLE_F_LISTEN_ALL_NSID       0x01
#define RTNL_HANDLE_F_SUPPRESS_NLERR        0x02
#define RTNL_HANDLE_F_STRICT_CHK        0x04
    int         flags;
};


static int 
libbpf_print_fn(enum libbpf_print_level level,
                const char *format,
                va_list args)
{
    return vfprintf(stderr, format, args);
}

static int
attr_put(struct nlmsghdr *n,
         int max,
         int type,
         const void *buf,
         int attr_len)
{
    int len = RTA_LENGTH(attr_len);
    int rv = -1;

    if (NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len) > max)
    {
        fprintf(stderr, "attr_put error: message longer than %d\n", max);
        rv = -1;
        goto out;
    }

    struct rtattr *rta = NULL;
    rta = NLMSG_TAIL(n);
    rta->rta_len = len;
    rta->rta_type = type;

    if (attr_len)
    {
        memcpy(RTA_DATA(rta), buf, attr_len);
    }

    n->nlmsg_len = NLMSG_ALIGN(n->nlmsg_len) + RTA_ALIGN(len);
    rv = 0;
out:
    return rv;
}

static int
attr_put_32(struct nlmsghdr *n,
            int max,
            int type,
            __u32 data)
{
    return attr_put(n, max, type, &data, sizeof(__u32));
}

static int
attr_put_str(struct nlmsghdr *n,
             int max,
             int type,
             const char *s)
{
    return attr_put(n, max, type, s, strlen(s)+1);
}

static void
rtnetlink_close(struct rtnetlink_handle *r)
{
    if (r->fd >= 0)
    {
        close(r->fd);
        r->fd = -1;
    }
}

static void
rtnetlink_send_error(struct nlmsgerr *err)
{
    fprintf(stderr, "rtnetlink replied: %s\n", strerror(-err->error));
}

static int
rtnetlink_open(struct rtnetlink_handle *rth)
{
    socklen_t address_len = 0;
    int sendbuf = 32 * 1024;
    int receivebuf = 1024 * 1024;
    int one = 1;
    int rv = -1;

    memset(rth, 0, sizeof(*rth));

    rth->proto = NETLINK_ROUTE;
    rth->fd = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (rth->fd < 0)
    {
        perror("cannot open netlink socket");
        rv = -1;
        goto out;
    }

    if (setsockopt(rth->fd, SOL_SOCKET, SO_SNDBUF,
               &sendbuf, sizeof(sendbuf)) < 0)
    {
        perror("error setsockopt sendbuf");
        rv = -1;
        goto out;
    }

    if (setsockopt(rth->fd, SOL_SOCKET, SO_RCVBUF,
               &receivebuf, sizeof(receivebuf)) < 0)
    {
        perror("error setsockopt receivebuf");
        rv = -1;
        goto out;
    }

    if (setsockopt(rth->fd, SOL_NETLINK, NETLINK_EXT_ACK,
           &one, sizeof(one)))
    {
        perror("error setsockopt netlink");
        rv = -1;
        goto out;
    }

    memset(&rth->local, 0, sizeof(rth->local));

    rth->local.nl_family = AF_NETLINK;
    rth->local.nl_groups = 0;

    if (bind(rth->fd, (struct sockaddr *)&rth->local,
         sizeof(rth->local)) < 0)
    {
        perror("failed to bind netlink socket");
        rv = -1;
        goto out;
    }
    address_len = sizeof(rth->local);
    if (getsockname(rth->fd, (struct sockaddr *)&rth->local,
            &address_len) < 0)
    {
        perror("error getsockname");
        rv = -1;
        goto out;
    }
    if (address_len != sizeof(rth->local))
    {
        fprintf(stderr, "bad address length %d\n", address_len);
        rv = -1;
        goto out;
    }
    if (rth->local.nl_family != AF_NETLINK)
    {
        fprintf(stderr, "bad address family %d\n",
            rth->local.nl_family);
        rv = -1;
        goto out;
    }

    rth->seq = time(NULL);
    rv = 0;
out:
    return rv;
}

static int
rtnetlink_recv(int fd, 
               struct msghdr *msg,
               char **answer)
{
    struct iovec *iov = msg->msg_iov;
    char *buf = NULL;
    int len = 0;
    int rv = 0;

    iov->iov_base = NULL;
    iov->iov_len = 0;

    do
    {
        len = recvmsg(fd, msg, MSG_PEEK | MSG_TRUNC);
    } while (len < 0 && (errno == EINTR || errno == EAGAIN));

    if (len <= 0)
    {
        fprintf(stderr, "netlink recv error \n");
        rv = len;
        goto out;
    }

    if (len < 32768)
    {
        len = 32768;
    }

    buf = malloc(len);
    if (!buf)
    {
        fprintf(stderr, "malloc error \n");
        rv = -ENOMEM;
        goto out;
    }

    iov->iov_base = buf;
    iov->iov_len = len;

    do
    {
        len = recvmsg(fd, msg, 0);
    } while (len < 0 && (errno == EINTR || errno == EAGAIN));

    if (len <= 0)
    {
        free(buf);
        fprintf(stderr, "netlink recv error \n");
        rv = len;
        goto out;
    }

    if (answer)
    {
        *answer = buf;
    }
    else
    {
        free(buf);
    }

    rv = len;
out:
    return rv;
}

static int
rtnetlink_send(struct rtnetlink_handle *rtnl, 
               struct nlmsghdr *nlmsg)
{
    struct iovec iov =
    {
        .iov_base = nlmsg,
        .iov_len = nlmsg->nlmsg_len
    };

    struct sockaddr_nl nladdr =
    {
        .nl_family = AF_NETLINK
    };

    struct msghdr msg =
    {
        .msg_name = &nladdr,
        .msg_namelen = sizeof(nladdr),
        .msg_iov = &iov,
        .msg_iovlen = 1,
    };

    unsigned int seq = 0;
    struct nlmsghdr *h = NULL;
    int recv_len = 0;
    char *buf = NULL;
    int rv = -1;

    h = iov.iov_base;
    h->nlmsg_seq = seq = ++rtnl->seq;
    /* request acknowledgement (NLMSG_ERROR packet) */
    h->nlmsg_flags |= NLM_F_ACK;

    if (sendmsg(rtnl->fd, &msg, 0) < 0)
    {
        perror("failure talking to rtnetlink");
        rv = -1;
        goto out;
    }

    /* switch to response iov */
    struct iovec riov;
    memset(&riov, 0, sizeof(riov));
    msg.msg_iov = &riov;
    msg.msg_iovlen = 1;

    recv_len = rtnetlink_recv(rtnl->fd, &msg, &buf);

    if (recv_len <= 0)
    {
        rv = -1;
        goto out;
    }

    if (msg.msg_namelen != sizeof(nladdr))
    {
        fprintf(stderr, "sender addr length == %d\n",
            msg.msg_namelen);
        rv = -1;
        goto out;
    }

    for (h = (struct nlmsghdr *)buf; recv_len >= sizeof(*h); )
    {
        int len = h->nlmsg_len;
        int l = len - sizeof(*h);

        if (l < 0 || len > recv_len)
        {
            if (msg.msg_flags & MSG_TRUNC)
            {
                fprintf(stderr, "truncated message\n");
                rv = -1;
                goto out;
            }
            fprintf(stderr, "bad message length: len=%d\n", len);
            rv = -1;
            goto out;
        }

        if (nladdr.nl_pid != 0 ||
            h->nlmsg_pid != rtnl->local.nl_pid ||
            h->nlmsg_seq > seq || h->nlmsg_seq < seq - 1)
        {
            /* skip this message. */
            recv_len -= NLMSG_ALIGN(len);
            h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
            continue;
        }

        /* Parse acknowledgment packet */
        if (h->nlmsg_type == NLMSG_ERROR)
        {
            struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(h);
            int error = err->error;

            if (l < sizeof(struct nlmsgerr))
            {
                fprintf(stderr, "error truncated\n");
                rv = -1;
                goto out;
            }

            if (error)
            {
                rtnetlink_send_error(err);
            }

            rv = error ? -1 : 0;
            goto out;
        }

        fprintf(stderr, "bad netlink reply\n");

        recv_len -= NLMSG_ALIGN(len);
        h = (struct nlmsghdr *)((char *)h + NLMSG_ALIGN(len));
    }

    if (msg.msg_flags & MSG_TRUNC)
    {
        fprintf(stderr, "message truncated\n");
        rv = -1;
        goto out;
    }

    if (recv_len)
    {
        fprintf(stderr, "uneven reply, remained: %d\n", recv_len);
        rv = -1;
        goto out;
    }

out:
    if (buf)
    {
        free(buf);
    }
    return rv;
}

static int 
netlink_qdisc(int cmd, 
              unsigned int flags)
{
    int rv = -1;
    struct rtnetlink_handle qdisc_rth = {0};
    struct 
    {
        struct nlmsghdr n;
        struct tcmsg    t;
        char        buf[MAX_MSG];
    } qdisc_req = 
    {
        .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
        .n.nlmsg_flags = NLM_F_REQUEST | flags,
        .n.nlmsg_type = cmd,
        .t.tcm_family = AF_UNSPEC,
    };

    if (rtnetlink_open(&qdisc_rth) < 0)
    {
        fprintf(stderr, "failed to open netlink\n");
        rv = -1;
        goto out;
    }
    qdisc_req.t.tcm_parent = TC_H_CLSACT;
    qdisc_req.t.tcm_handle = TC_H_MAKE(TC_H_CLSACT, 0);
    attr_put(&qdisc_req.n, sizeof(qdisc_req), TCA_KIND, "clsact", strlen("clsact") + 1);

    qdisc_req.t.tcm_ifindex = if_nametoindex(IFNAME_TO_ATTACH_TO);
    if (qdisc_req.t.tcm_ifindex == 0)
    {
        fprintf(stderr, "failed to find device %s\n", IFNAME_TO_ATTACH_TO);
        rv = -1;
        goto out;
    } 
    /* talk to netlink */
    if (rtnetlink_send(&qdisc_rth, &qdisc_req.n) < 0)
    {
        fprintf(stderr, "error talking to the kernel (rtnetlink_send)\n");
        rv = -1;
        goto out;
    }

    rv = 0;
out:
    rtnetlink_close(&qdisc_rth);
    return rv;
}

static int 
netlink_qdisc_add()
{
    return netlink_qdisc(RTM_NEWQDISC, NLM_F_EXCL | NLM_F_CREATE);
}

static int
netlink_qdisc_del()
{
    return netlink_qdisc(RTM_DELQDISC, 0);
}

struct rtattr *tail;
struct rtnetlink_handle filter_rth = {0};

struct
{
    struct nlmsghdr n;
    struct tcmsg    t;
    char        buf[MAX_MSG];
} filter_req =
{
    .n.nlmsg_len = NLMSG_LENGTH(sizeof(struct tcmsg)),
    .n.nlmsg_flags = NLM_F_REQUEST | NLM_F_EXCL | NLM_F_CREATE,
    .n.nlmsg_type = RTM_NEWTFILTER,
    .t.tcm_family = AF_UNSPEC,
};

static int 
netlink_filter_add_begin()
{
    int rv = -1;

    if (rtnetlink_open(&filter_rth) < 0)
    {
        fprintf(stderr, "failed to open netlink\n");
        rtnetlink_close(&filter_rth);
        rv = -1;
        goto out;
    }

    __u32 protocol = htons(ETH_P_ALL);
    filter_req.t.tcm_parent = TC_H_MAKE(TC_H_CLSACT, TC_H_MIN_EGRESS);
    filter_req.t.tcm_info = TC_H_MAKE(0 << 16, protocol);
    attr_put(&filter_req.n, sizeof(filter_req), TCA_KIND, "bpf", strlen("bpf") + 1);
    
    filter_req.t.tcm_ifindex = if_nametoindex(IFNAME_TO_ATTACH_TO);
    if (filter_req.t.tcm_ifindex == 0)
    {
        fprintf(stderr, "failed to find device %s\n", IFNAME_TO_ATTACH_TO);
        rtnetlink_close(&filter_rth);
        rv = -1;
        goto out;
    } 

    struct nlmsghdr *n = &filter_req.n;
    tail = (struct rtattr *)(((void *)n) + NLMSG_ALIGN(n->nlmsg_len));
    attr_put(n, MAX_MSG, TCA_OPTIONS, NULL, 0);
    
    rv = 0;
out:
    return rv;
}

static int 
netlink_filter_add_end(int fd)
{
    struct nlmsghdr *nl = &filter_req.n;
    int rv = -1;

    attr_put_32(nl, MAX_MSG, TCA_BPF_FD, fd);
    attr_put_str(nl, MAX_MSG, TCA_BPF_NAME, EBPF_OBJ_FILE_NAME ":[.text]");
    attr_put_32(nl, MAX_MSG, TCA_BPF_FLAGS, TCA_BPF_FLAG_ACT_DIRECT);   
    tail->rta_len = (((void *)nl) + nl->nlmsg_len) - (void *)tail;

    /* talk to netlink */
    if (rtnetlink_send(&filter_rth, &filter_req.n) < 0)
    {
        fprintf(stderr, "error talking to the kernel (rtnetlink_send)\n");
        rv = -1;
        goto out;
    }

    rv = 0;
out:
    rtnetlink_close(&filter_rth);
    return rv;
}

int 
main(int argc, 
     char **argv)
{
    struct bpf_program *prog = NULL;
    struct bpf_program *p = NULL;
    struct bpf_object *obj = NULL;
    struct bpf_map *map = NULL;
    int prog_fd_dupd = 0;
    int rv = -1;

    /* do the same things as 'tc qdisc del dev <iface> clsact' */
    if (netlink_qdisc_del() != 0)
    {
        fprintf(stderr, "failed to del qdisc\n");
    }
    else
    {
        printf("DELETED QDISC\n");
    }

    /* if 'unload' is passed as arg, only delete qdisc */
    if (argc > 1 && !strcmp(argv[1], "unload"))
    {
        rv = 0;
        goto out;
    }

    /* 'tc qdisc add dev <iface> clsact' */
    if (netlink_qdisc_add() != 0)
    {
        fprintf(stderr, "failed to add qdisc\n");
        rv = -1;
        goto out;
    }

    printf("ADDED QDISC\n");

    /* 'tc filter add dev <iface> egress bpf da obj <ebpf_file> sec .text' */
    /* finished when netlink_filter_add_end() is called */
    if (netlink_filter_add_begin() != 0)
    {
        fprintf(stderr, "filter_add_begin() failed\n");
        rv = -1;
        goto out;
    }

    if (mkdir("/sys/fs/bpf/tc/globals", 0700) && errno != EEXIST)
    {
        fprintf(stderr, "failed to create directory: /sys/fs/bpf/tc/globals\n");
        rv = -1;
        goto out;
    }

    libbpf_set_print(libbpf_print_fn);

    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, open_opts,
        .relaxed_maps = true,
        .pin_root_path = "/sys/fs/bpf/tc/globals",
    );

    obj = bpf_object__open_file(EBPF_OBJ_FILE_NAME, &open_opts);
    if (!obj || libbpf_get_error(obj))
    {
        fprintf(stderr, "failed to open BPF object\n");
        rv = -1;
        goto out;
    }
    printf("BPF FILE OPENED\n");

    bpf_object__for_each_program(p, obj)
    {
        bpf_program__set_type(p, BPF_PROG_TYPE_SCHED_CLS);
        bpf_program__set_ifindex(p, 0); //?
        if (!prog)
            prog = p;
    }
    bpf_object__for_each_map(map, obj)
    {
        bpf_map__set_ifindex(map, 0); //?
        bpf_map__set_pin_path(map, "/sys/fs/bpf/tc/globals/allowed_IPs");
    }

    rv = bpf_object__load(obj);
    if (rv)
    {
        fprintf(stderr, "failed to load BPF program\n");
        bpf_object__close(obj);
        rv = -1;
        goto out;
    }
    printf("BPF PROG LOADED\n");

    prog_fd_dupd = fcntl(bpf_program__fd(prog), F_DUPFD_CLOEXEC, 1);
    if (prog_fd_dupd < 0)
    {
        printf("bad prog_fd_dupd\n");
        bpf_object__close(obj);
        rv = -1;
        goto out;
    }
    
    bpf_object__close(obj);
    obj = NULL;

    /* tc filter add continued */
    if (netlink_filter_add_end(prog_fd_dupd) != 0)
    {
        fprintf(stderr, "filter_add_end() failed\n");
        rv = -1;
        goto out;
    }

    printf("BPF PROG ATTACHED TO TC\n");

    rv = 0;

out:
    return rv;
}
