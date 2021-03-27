// TODO:
// LICENSE
//
// Host Isolation demo eBPF program #2
//
// Based on tcpconnect(8) from BCC by Brendan Gregg

#include "kerneldefs.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

#define BPF_ANY 0 //TODO include uapi/linux/bpf.h
#define BPF_NOEXIST 1

// TODO: shouldnt be necessary to redefine - check if we have __KERNEL__ flag -> the kernel ptrace.h should be included, not the userspace one
#define PT_REGS_PARM2(x) ((x)->si)

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
    //important: define ARCH beforehand so that PT_REGS macro gets args for proper arch
    struct sockaddr *uaddr = (struct sockaddr*)PT_REGS_PARM2(ctx);

    return enter_tcp_connect(ctx, uaddr);
}

char LICENSE[] SEC("license") = "GPL";

