// TODO:
// LICENSE
//
// Host Isolation - tool for updating map of allowed IPs
//
#include <argp.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>

#define warn(...) fprintf(stderr, __VA_ARGS__)

static int libbpf_print_fn(enum libbpf_print_level level,
        const char *format, va_list args)
{
    //if (level == LIBBPF_DEBUG && !env.verbose)
//      return 0;
    return vfprintf(stderr, format, args);
}

int main(int argc, char **argv)
{
    int map_IPs_fd;
    int rv = 0;
    uint32_t key, val;

    libbpf_set_print(libbpf_print_fn);

    map_IPs_fd = bpf_obj_get("/sys/fs/bpf/tc/globals/allowed_IPs");
    if (map_IPs_fd < 0) {
        rv = -1;
        goto cleanup;
    }

    val = 1;
    inet_pton(AF_INET, "172.67.197.155", &key);
    rv = bpf_map_update_elem(map_IPs_fd, &key, &val, 0);
    if (rv) {
        warn("failed to add to IPs BPF map \n");
        goto cleanup;
    }
    inet_pton(AF_INET, "104.21.34.41", &key);
    rv = bpf_map_update_elem(map_IPs_fd, &key, &val, 0);
    if (rv) {
        warn("failed to add to IPs BPF map \n");
        goto cleanup;
    }

    printf("BPF IP MAP UPDATED\n");

cleanup:
    if (map_IPs_fd >= 0)
        close(map_IPs_fd);
        if (rv)
                warn("failure - run with sudo or make sure /sys/fs/bpf/tc/globals/allowed_IPs exists\n");

    return rv;
}
