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

static int
libbpf_print_fn(enum libbpf_print_level level,
                const char *format,
                va_list args)
{
    return vfprintf(stderr, format, args);
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
    printf("BPF FILE OPENED\n");

    ip_map = bpf_object__find_map_by_name(obj, "allowed_IPs");
    if (!ip_map || libbpf_get_error(ip_map))
    {
        printf("failed to load BPF map\n");
        rv = -1;
        goto cleanup;
    }
    printf("BPF MAP LOADED\n");

    result = bpf_map__set_pin_path(ip_map, "/sys/fs/bpf/tc/globals/allowed_IPs");
    if (result)
    {
        printf("error setting pin path for map\n");
    }

    /* pin allowed_pids map when program is loaded */
    pids_map = bpf_object__find_map_by_name(obj, "allowed_pids");
    if (!pids_map || libbpf_get_error(pids_map))
    {
        printf("failed to load BPF map\n");
        rv = -1;
        goto cleanup;
    }
    printf("BPF MAP #2 LOADED\n");

    result = bpf_map__set_pin_path(pids_map, "/sys/fs/bpf/allowed_pids");
    if (result)
    {
        printf("error setting pin path for map\n");
    }

    prog_fd = bpf_object__load(obj);
    if (prog_fd < 0)
    {
        printf("failed to load BPF program\n");
        rv = -1;
        goto cleanup;
    }
    printf("BPF PROG LOADED\n");

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
    printf("BPF PROG ATTACHED\n");

    // eBPF program is detached by the kernel when process terminates
    sleep(10*60*60*60);

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
