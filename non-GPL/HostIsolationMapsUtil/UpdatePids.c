// TODO:
// LICENSE
//
// Host Isolation - tool for updating map of allowed PIDs
//
#include <argp.h>
#include <unistd.h>
#include <time.h>
#include <arpa/inet.h>

#include <Common.h>
#include "UpdateMaps.h"

int
main(int argc,
     char **argv)
{
    int rv = 0;
    uint32_t pid = 0;

    ebpf_set_log_func(ebpf_default_log_func());

    if (argc != 2)
    {
        printf("You need to pass a PID number as an argument\n");
        rv = -1;
        goto cleanup;
    }

    if (sscanf(argv[1], "%u", &pid) != 1)
    {
        printf("Error parsing string\n");
        rv = -1;
        goto cleanup;
    }

    rv = ebpf_map_allowed_pids_add(pid);

    if (rv == 0)
        printf("PID %u added to " EBPF_ALLOWED_PIDS_MAP_NAME " BPF map!\n", pid);

cleanup:

    return rv;
}
