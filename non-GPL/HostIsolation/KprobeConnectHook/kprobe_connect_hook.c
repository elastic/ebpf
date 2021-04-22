// TODO:
// LICENSE
//
// Host Isolation standalone demo
// Loader for eBPF program #2 (attaches to tcp_v4_connect kprobe)
// 
#include <argp.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>
#include <sys/stat.h>

// enable debug logging
#define DEBUG

#ifdef DEBUG
#define dbg_printf(fmt, ...) printf(fmt, ##__VA_ARGS__)
#else
#define dbg_printf(fmt, ...)
#endif

static int
libbpf_print_fn(enum libbpf_print_level level,
                const char *format,
                va_list args)
{
#ifdef DEBUG
    return vfprintf(stderr, format, args);
#else
    return 0;
#endif
}

int
main(int argc,
     char **argv)
{
    struct bpf_program *prog = NULL;
    struct bpf_object *obj = NULL;
    struct bpf_link *link = NULL;
    struct bpf_map *ip_map = NULL;
    struct bpf_map *pids_map = NULL;
    int prog_fd = -1;
    int rv = 0, result = 0;

    libbpf_set_print(libbpf_print_fn);

    obj = bpf_object__open_file("./kprobe_connect_hook.bpf.o", NULL);
    if (!obj || libbpf_get_error(obj))
    {
        printf("failed to open BPF object\n");
        rv = -1;
        goto cleanup;
    }
    dbg_printf("BPF FILE OPENED\n");

    ip_map = bpf_object__find_map_by_name(obj, "allowed_IPs");
    if (!ip_map || libbpf_get_error(ip_map))
    {
        printf("failed to load allowed_IPs BPF map\n");
        rv = -1;
        goto cleanup;
    }
    dbg_printf("BPF ALLOWED_IPS MAP LOADED\n");

    result = bpf_map__set_pin_path(ip_map, "/sys/fs/bpf/tc/globals/allowed_IPs");
    if (result)
    {
        printf("failed to set pin path for allowed_IPs map\n");
        rv = -1;
        goto cleanup;
    }

    // create elastic/endpoint dir in bpf fs
    if (mkdir("/sys/fs/bpf/elastic", 0700) && errno != EEXIST)
    {
        printf("failed to create /sys/fs/bpf/elastic dir, err=%d\n", errno);
        rv = -1;
        goto cleanup;
    }
    if (mkdir("/sys/fs/bpf/elastic/endpoint", 0700) && errno != EEXIST)
    {
        printf("failed to create /sys/fs/bpf/elastic/endpoint dir, err=%d\n", errno);
        rv = -1;
        goto cleanup;
    }

    // pin allowed_pids map when program is loaded
    pids_map = bpf_object__find_map_by_name(obj, "allowed_pids");
    if (!pids_map || libbpf_get_error(pids_map))
    {
        printf("failed to load allowed_pids BPF map\n");
        rv = -1;
        goto cleanup;
    }
    dbg_printf("BPF ALLOWED_PIDS MAP LOADED\n");

    result = bpf_map__set_pin_path(pids_map, "/sys/fs/bpf/elastic/endpoint/allowed_pids");
    if (result)
    {
        printf("failed to set pin path for allowed_pids map\n");
        rv = -1;
        goto cleanup;
    }

    prog_fd = bpf_object__load(obj);
    if (prog_fd < 0)
    {
        printf("failed to load BPF program\n");
        rv = -1;
        goto cleanup;
    }
    dbg_printf("BPF PROGRAM LOADED\n");

    prog = bpf_object__find_program_by_title(obj, "kprobe/tcp_v4_connect");
    if (!prog || libbpf_get_error(prog))
    {
        printf("failed to find BPF program by name\n");
        rv = -1;
        goto cleanup;
    }

    link = bpf_program__attach(prog);
    if (!link || libbpf_get_error(link))
    {
        printf("failed to attach BPF program\n");
        rv = -1;
        goto cleanup;
    }
    dbg_printf("BPF PROGRAM ATTACHED TO KPROBE\n");

    // eBPF program is detached by the kernel when process terminates
    // sleep forever
    while(1);

cleanup:
    if (link && !libbpf_get_error(link))
    {
        bpf_link__destroy(link);
    }
    if (obj && !libbpf_get_error(obj))
    {
        bpf_object__close(obj);
    }

    return rv;
}
