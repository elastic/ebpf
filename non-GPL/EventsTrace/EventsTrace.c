// SPDX-License-Identifier: LicenseRef-Elastic-License-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License 2.0;
 * you may not use this file except in compliance with the Elastic License 2.0.
 */

#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <signal.h>

#define __aligned_u64 __u64 __attribute__((aligned(8)))
#include <LibEbpfEvents.h>

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
    exiting = 1;
    fprintf(stdout, "Received SIGINT, Exiting...\n");
}

static void ebpf_file_event_path__tostring(struct ebpf_event_file_path path, char *pathbuf)
{
    strcpy(pathbuf, "/");
    for (int i = 0; i < path.patharray_len; i++)
    {
        strcat(pathbuf, path.path_array[i]);

        if (i != path.patharray_len - 1)
        {
            strcat(pathbuf, "/");
        }
    }
}

static int event_ctx_callback(struct ebpf_event *evt, size_t size)
{
    if (evt->data == NULL)
    {
        printf("[SKIP] Event with no data\n");
        return 0;
    }

    switch(evt->type)
    {
        case EBPF_EVENT_FILE_DELETE:
        {
            struct ebpf_event_file_delete_data *evt_data =
                (struct ebpf_event_file_delete_data *)evt->data;
            char pathbuf[MAX_FILEPATH_LENGTH];
            ebpf_file_event_path__tostring(evt_data->path, pathbuf);
            printf("[EBPF_EVENT_FILE_DELETE]: pid: %d path: %s\n", evt_data->pid, pathbuf);
        }

        case EBPF_EVENT_PROCESS_FORK:
        {
            struct ebpf_event_process_fork_data *evt_data =
                (struct ebpf_event_process_fork_data *)evt->data;
            printf("[EBPF_EVENT_PROCESS_FORK]: parent_pid: %d child_pid: %d\n",
                    evt_data->parent_pid, evt_data->child_pid);
            break;
        }

        case EBPF_EVENT_PROCESS_EXEC:
        {
            struct ebpf_event_process_exec_data *evt_data =
                (struct ebpf_event_process_exec_data *)evt->data;
            printf("[EBPF_EVENT_PROCESS_EXEC]: pid: %d\n", evt_data->pid);
            break;
        }
    }

    return 0;
}

int main(int argc, char const *argv[])
{
    int err = 0;
    struct FileEvents_bpf *probe = NULL;

    if (signal(SIGINT, sig_int) == SIG_ERR)
    {
        fprintf(stderr, "Failed to register SIGINT handler\n");
        goto cleanup;
    }

    struct ebpf_event_ctx *ctx;
    uint64_t features = EBPF_KERNEL_FEATURE_BPF;
    uint64_t events = EBPF_EVENT_FILE_DELETE;
    ebpf_event_ctx__new(&ctx, event_ctx_callback, features, events);

    while (!exiting)
    {
        err = ebpf_event_ctx__next(ctx);
        if (err < 0)
        {
            fprintf(stderr, "Failed to poll event context\n");
            break;
        }
    }

cleanup:
    if (probe)
    {
        ebpf_event_ctx__destroy(ctx);
    }
    return err != 0;
}
