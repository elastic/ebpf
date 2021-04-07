// TODO:
// LICENSE
//
// Host Isolation - this eBPF program hooks into tcp_v4_connect kprobe and adds
// entries to the IP allowlist if an allowed process tries to initiate a connection.

// flag needed to pick the right PT_REGS macros in bpf_tracing.h
#define __KERNEL__

#include "kerneldefs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
// taken from libbpf uapi include dir
#include <linux/bpf.h>

#define NULL 0

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} allowed_IPs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(int));
    __uint(max_entries, 64);
} allowed_pids SEC(".maps");

static __always_inline void
add_IP_to_allowlist(__u32 daddr)
{
    // add new entry
    u32 val = 1;
    long rv = bpf_map_update_elem(&allowed_IPs, &daddr, &val, BPF_NOEXIST);
    if (rv)
    {
        char errmsg[] = "Error updating hashmap\n";
        bpf_trace_printk(errmsg, sizeof(errmsg));
    }

    char x[] = "NEW IP: %u.%u.%u\n";
    bpf_trace_printk(x, sizeof(x),
                        (unsigned char)(daddr & 0xFF),
                        (unsigned char)(0xFF & (unsigned char)(daddr >> 8)),
                        (unsigned char)(0xFF & (unsigned char)(daddr >> 16))
                        );
}

static __always_inline int
enter_tcp_connect(struct pt_regs *ctx,
                  struct sockaddr *uaddr)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = pid_tgid >> 32;
    __u32 *elem = NULL;
    __u32 daddr = 0;

    struct sockaddr_in *sin = (struct sockaddr_in*)uaddr;
    bpf_probe_read(&daddr, sizeof(daddr), &sin->sin_addr.s_addr);

    // check if pid is allowed
    elem = bpf_map_lookup_elem(&allowed_pids, &pid);

    if (!elem)
    {
        return 0;
    }

    add_IP_to_allowlist(daddr);

    return 0;
}

SEC("kprobe/tcp_v4_connect")
int
tcp_v4_connect__entry(struct pt_regs *ctx) //struct sock *sk, struct sockaddr *uaddr)
{
    // important: define ARCH env var so that PT_REGS macro gets args for the proper arch
    struct sockaddr *uaddr = (struct sockaddr*)PT_REGS_PARM2(ctx);

    return enter_tcp_connect(ctx, uaddr);
}

char LICENSE[] SEC("license") = "GPL";

