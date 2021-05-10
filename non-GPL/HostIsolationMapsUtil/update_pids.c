// TODO:
// LICENSE
//
// Host Isolation - tool for updating map of allowed PIDs
//
#include <argp.h>
#include <unistd.h>
#include <time.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <arpa/inet.h>

#include <Common.h>

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
    int map_PIDs_fd = -1;
    int rv = 0;
    uint32_t key = 0, val = 0;

    if (argc != 2)
    {
        printf("You need to pass a PID number as an argument\n");
        rv = -1;
        goto cleanup;
    }

    libbpf_set_print(libbpf_print_fn);

    if (sscanf(argv[1], "%u", &key) != 1)
    {
        printf("Error parsing string\n");
        rv = -1;
        goto cleanup;
    }

    // values are not used in the hash map
    val = 1;

    map_PIDs_fd = bpf_obj_get(EBPF_ALLOWED_PIDS_MAP_PATH);
    if (map_PIDs_fd < 0)
    {
        printf("Error: run with sudo or make sure " EBPF_ALLOWED_PIDS_MAP_PATH " exists\n");
        rv = -1;
        goto cleanup;
    }

    rv = bpf_map_update_elem(map_PIDs_fd, &key, &val, 0);
    if (rv)
    {
        printf("Error: failed to add PID to BPF map \n");
        goto cleanup;
    }

    printf("PID %u added to " EBPF_ALLOWED_PIDS_MAP_NAME " BPF map!\n", key);

cleanup:
    if (map_PIDs_fd >= 0)
    {
        close(map_PIDs_fd);
    }

    return rv;
}
