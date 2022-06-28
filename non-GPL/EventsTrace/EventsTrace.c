// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#include <argp.h>
#include <ctype.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/time.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#define __aligned_u64 __u64 __attribute__((aligned(8)))
#include <LibEbpfEvents.h>

const char *argp_program_version     = "EventsTrace 0.0.0";
const char *argp_program_bug_address = "https://github.com/elastic/ebpf/issues";
const char argp_program_doc[] =
    "Command line to trace Process, Network and File Events\n"
    "\n"
    "This program traces Process, Network and File Events\ncoming from the LibEbpfEvents library\n"
    "\n"
    "USAGE: ./EventsTrace [--all|-a] [--file-delete] [--file-create] [--file-rename]\n"
    "[--process-fork] [--process-exec] [--process-exit] [--process-setsid] [--process-setuid] "
    "[--process-setgid] [--process-tty-write]\n"
    "[--net-conn-accept] [--net-conn-attempt] [--net-conn-closed]\n"
    "[--print-initialized] [--unbuffer-stdout] [--libbpf-verbose]\n";

static const struct argp_option opts[] = {
    {"print-initialized", 'i', NULL, false,
     "Whether or not to print a message when probes have been successfully loaded", 1},
    {"unbuffer-stdout", 'u', NULL, false, "Don't buffer stdout in userspace at all", 1},
    {"libbpf-verbose", 'v', NULL, false, "Log verbose libbpf logs to stderr", 1},
    {"all", 'a', NULL, false, "Whether or not to consider all the events", 0},
    {"file-delete", EBPF_EVENT_FILE_DELETE, NULL, false,
     "Whether or not to consider file delete events", 1},
    {"file-create", EBPF_EVENT_FILE_CREATE, NULL, false,
     "Whether or not to consider file create events", 1},
    {"file-rename", EBPF_EVENT_FILE_RENAME, NULL, false,
     "Whether or not to consider file rename events", 1},
    {"process-fork", EBPF_EVENT_PROCESS_FORK, NULL, false,
     "Whether or not to consider process fork events", 1},
    {"process-exec", EBPF_EVENT_PROCESS_EXEC, NULL, false,
     "Whether or not to consider process exec events", 1},
    {"process-exit", EBPF_EVENT_PROCESS_EXIT, NULL, false,
     "Whether or not to consider process exit events", 1},
    {"process-setsid", EBPF_EVENT_PROCESS_SETSID, NULL, false,
     "Whether or not to consider process setsid events", 1},
    {"process-setuid", EBPF_EVENT_PROCESS_SETUID, NULL, false,
     "Whether or not to consider process setuid events", 1},
    {"process-setgid", EBPF_EVENT_PROCESS_SETGID, NULL, false,
     "Whether or not to consider process setgid events", 1},
    {"process-tty-write", EBPF_EVENT_PROCESS_TTY_WRITE, NULL, false,
     "Whether or not to consider process tty-write events", 1},
    {"net-conn-accept", EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED, NULL, false,
     "Whether or not to consider network connection accepted events", 1},
    {"net-conn-attempt", EBPF_EVENT_NETWORK_CONNECTION_ATTEMPTED, NULL, false,
     "Whether or not to consider network connection attempted events", 1},
    {"net-conn-closed", EBPF_EVENT_NETWORK_CONNECTION_CLOSED, NULL, false,
     "Whether or not to consider network connection closed events", 1},
    {"features-autodetect", 'd', NULL, false, "Autodetect features based on running kernel", 2},
    {"set-bpf-tramp", EBPF_FEATURE_BPF_TRAMP, NULL, false, "Set feature supported: bpf trampoline",
     2},
    {},
};

uint64_t g_events_env          = 0;
uint64_t g_features_env        = 0;
uint64_t g_features_autodetect = 0;

bool g_print_initialized = 0;
bool g_unbuffer_stdout   = 0;
bool g_libbpf_verbose    = 0;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        g_print_initialized = 1;
        break;
    case 'u':
        g_unbuffer_stdout = 1;
        break;
    case 'v':
        g_libbpf_verbose = 1;
        break;
    case 'a':
        g_events_env = UINT64_MAX;
        break;
    case 'd':
        g_features_autodetect = 1;
        break;
    case EBPF_EVENT_FILE_DELETE:
    case EBPF_EVENT_FILE_CREATE:
    case EBPF_EVENT_FILE_RENAME:
    case EBPF_EVENT_PROCESS_FORK:
    case EBPF_EVENT_PROCESS_EXEC:
    case EBPF_EVENT_PROCESS_EXIT:
    case EBPF_EVENT_PROCESS_SETSID:
    case EBPF_EVENT_PROCESS_SETUID:
    case EBPF_EVENT_PROCESS_SETGID:
    case EBPF_EVENT_PROCESS_TTY_WRITE:
    case EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED:
    case EBPF_EVENT_NETWORK_CONNECTION_ATTEMPTED:
    case EBPF_EVENT_NETWORK_CONNECTION_CLOSED:
        g_events_env |= key;
        break;
    case EBPF_FEATURE_BPF_TRAMP:
        g_features_env |= key;
        break;
    case ARGP_KEY_ARG:
        argp_usage(state);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser  = parse_arg,
    .doc     = argp_program_doc,
};

static volatile sig_atomic_t exiting = 0;

static void sig_int(int signo)
{
    exiting = 1;
    fprintf(stdout, "Received SIGINT, Exiting...\n");
}

static void out_comma()
{
    printf(",");
}

static void out_newline()
{
    printf("\n");
}

static void out_object_start()
{
    printf("{");
}

static void out_object_end()
{
    printf("}");
}

static void out_event_type(const char *type)
{
    printf("\"event_type\":\"%s\"", type);
}

static void out_uint(const char *name, const unsigned long value)
{
    printf("\"%s\":%lu", name, value);
}

static void out_int(const char *name, const long value)
{
    printf("\"%s\":%ld", name, value);
}

static void out_string(const char *name, const char *value)
{
    printf("\"%s\":\"", name);
    for (size_t i = 0; i < strlen(value); i++) {
        char c = value[i];
        switch (c) {
        case '\n':
            printf("\\n");
            break;
        case '\r':
            printf("\\r");
            break;
        case '\\':
            printf("\\\\");
            break;
        case '"':
            printf("\"");
            break;
        case '\t':
            printf("\\t");
            break;
        case '\b':
            printf("\\b");
            break;
        default:
            if (!isascii(c) || iscntrl(c))
                printf("\\x%02x", c);
            else
                printf("%c", c);
        }
    }

    printf("\"");
}

static void out_tty_dev(const char *name, struct ebpf_tty_dev *tty_dev)
{
    printf("\"%s\":", name);
    out_object_start();
    out_int("major", tty_dev->major);
    out_comma();
    out_int("minor", tty_dev->minor);
    out_object_end();
}

static void out_pid_info(const char *name, struct ebpf_pid_info *pid_info)
{
    printf("\"%s\":", name);
    out_object_start();
    out_int("tid", pid_info->tid);
    out_comma();
    out_int("tgid", pid_info->tgid);
    out_comma();
    out_int("ppid", pid_info->ppid);
    out_comma();
    out_int("pgid", pid_info->pgid);
    out_comma();
    out_int("sid", pid_info->sid);
    out_comma();
    out_uint("start_time_ns", pid_info->start_time_ns);
    out_object_end();
}

static void out_cred_info(const char *name, struct ebpf_cred_info *cred_info)
{
    printf("\"%s\":", name);
    out_object_start();
    out_int("ruid", cred_info->ruid);
    out_comma();
    out_int("rgid", cred_info->rgid);
    out_comma();
    out_int("euid", cred_info->euid);
    out_comma();
    out_int("egid", cred_info->egid);
    out_comma();
    out_int("suid", cred_info->suid);
    out_comma();
    out_int("sgid", cred_info->sgid);
    out_object_end();
}

static void out_argv(const char *name, char *buf, size_t buf_size)
{
    // Buf is the argv array, with each argument delimited by a '\0', rework
    // it in a scratch space so it's a space-separated string we can print
    char scratch_space[buf_size];
    memcpy(scratch_space, buf, buf_size);

    for (int i = 0; i < buf_size; i++) {
        if (scratch_space[i] == '\0')
            scratch_space[i] = ' ';
    }

    for (int i = buf_size - 2; i >= 0; i--) {
        if (scratch_space[i] != ' ') {
            scratch_space[i + 1] = '\0';
            break;
        }
    }

    out_string(name, scratch_space);
}

static void out_file_delete(struct ebpf_file_delete_event *evt)
{
    out_object_start();
    out_event_type("FILE_DELETE");
    out_comma();

    out_pid_info("pids", &evt->pids);
    out_comma();

    out_string("path", evt->path);
    out_comma();

    out_int("mount_namespace", evt->mntns);
    out_comma();

    out_string("comm", (const char *)&evt->comm);

    out_object_end();
    out_newline();
}

static void out_file_create(struct ebpf_file_create_event *evt)
{
    out_object_start();
    out_event_type("FILE_CREATE");
    out_comma();

    out_pid_info("pids", &evt->pids);
    out_comma();

    out_string("path", evt->path);
    out_comma();

    out_int("mount_namespace", evt->mntns);
    out_comma();

    out_string("comm", (const char *)&evt->comm);

    out_object_end();
    out_newline();
}

static void out_file_rename(struct ebpf_file_rename_event *evt)
{
    out_object_start();
    out_event_type("FILE_RENAME");
    out_comma();

    out_pid_info("pids", &evt->pids);
    out_comma();

    out_string("old_path", evt->old_path);
    out_comma();

    out_string("new_path", evt->new_path);
    out_comma();

    out_int("mount_namespace", evt->mntns);
    out_comma();

    out_string("comm", (const char *)&evt->comm);

    out_object_end();
    out_newline();
}

static void out_process_fork(struct ebpf_process_fork_event *evt)
{
    out_object_start();
    out_event_type("PROCESS_FORK");
    out_comma();

    out_pid_info("parent_pids", &evt->parent_pids);
    out_comma();

    out_pid_info("child_pids", &evt->child_pids);
    out_comma();

    out_string("pids_ss_cgroup_path", evt->pids_ss_cgroup_path);

    out_object_end();
    out_newline();
}

static void out_process_exec(struct ebpf_process_exec_event *evt)
{
    out_object_start();
    out_event_type("PROCESS_EXEC");
    out_comma();

    out_pid_info("pids", &evt->pids);
    out_comma();

    out_cred_info("creds", &evt->creds);
    out_comma();

    out_tty_dev("ctty", &evt->ctty);
    out_comma();

    out_string("filename", evt->filename);
    out_comma();

    out_string("cwd", evt->cwd);
    out_comma();

    out_string("pids_ss_cgroup_path", evt->pids_ss_cgroup_path);
    out_comma();

    out_argv("argv", evt->argv, sizeof(evt->argv));

    out_object_end();
    out_newline();
}

static void out_process_setsid(struct ebpf_process_setsid_event *evt)
{
    out_object_start();
    out_event_type("PROCESS_SETSID");
    out_comma();

    out_pid_info("pids", &evt->pids);

    out_object_end();
    out_newline();
}

static void out_process_setuid(struct ebpf_process_setuid_event *evt)
{
    out_object_start();
    out_event_type("PROCESS_SETUID");
    out_comma();

    out_pid_info("pids", &evt->pids);
    out_comma();
    out_uint("new_ruid", evt->new_ruid);
    out_comma();
    out_uint("new_euid", evt->new_euid);

    out_object_end();
    out_newline();
}

static void out_process_setgid(struct ebpf_process_setgid_event *evt)
{
    out_object_start();
    out_event_type("PROCESS_SETGID");
    out_comma();

    out_pid_info("pids", &evt->pids);
    out_comma();
    out_uint("new_rgid", evt->new_rgid);
    out_comma();
    out_uint("new_egid", evt->new_egid);

    out_object_end();
    out_newline();
}

static void out_process_tty_write(struct ebpf_process_tty_write_event *evt)
{
    out_object_start();
    out_event_type("PROCESS_TTY_WRITE");
    out_comma();

    out_pid_info("pids", &evt->pids);
    out_comma();
    out_int("tty_out_len", evt->tty_out_len);
    out_comma();
    out_int("tty_out_truncated", evt->tty_out_truncated);
    out_comma();
    out_string("tty_out", evt->tty_out);

    out_object_end();
    out_newline();
}

static void out_process_exit(struct ebpf_process_exit_event *evt)
{
    out_object_start();
    out_event_type("PROCESS_EXIT");
    out_comma();

    out_pid_info("pids", &evt->pids);
    out_comma();

    out_string("pids_ss_cgroup_path", evt->pids_ss_cgroup_path);
    out_comma();

    out_int("exit_code", evt->exit_code);

    out_object_end();
    out_newline();
}

static void out_ip_addr(const char *name, const void *addr)
{
    char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, addr, buf, sizeof(buf));
    printf("\"%s\":\"%s\"", name, buf);
}

static void out_ip6_addr(const char *name, const void *addr)
{
    char buf[INET6_ADDRSTRLEN];
    inet_ntop(AF_INET6, addr, buf, sizeof(buf));
    printf("\"%s\":\"%s\"", name, buf);
}

static void out_net_info(const char *name, struct ebpf_net_event *evt)
{
    struct ebpf_net_info *net = &evt->net;

    printf("\"%s\":", name);
    out_object_start();

    switch (net->transport) {
    case EBPF_NETWORK_EVENT_TRANSPORT_TCP:
        out_string("transport", "TCP");
        out_comma();
        break;
    }

    switch (net->family) {
    case EBPF_NETWORK_EVENT_AF_INET:
        out_string("family", "AF_INET");
        out_comma();

        out_ip_addr("source_address", &net->saddr);
        out_comma();

        out_int("source_port", net->sport);
        out_comma();

        out_ip_addr("destination_address", &net->daddr);
        out_comma();

        out_int("destination_port", net->dport);
        break;
    case EBPF_NETWORK_EVENT_AF_INET6:
        out_string("family", "AF_INET6");
        out_comma();

        out_ip6_addr("source_address", &net->saddr6);
        out_comma();

        out_int("source_port", net->sport);
        out_comma();

        out_ip6_addr("destination_address", &net->daddr6);
        out_comma();

        out_int("destination_port", net->dport);
        break;
    }

    out_comma();
    out_int("network_namespace", net->netns);

    switch (evt->hdr.type) {
    case EBPF_EVENT_NETWORK_CONNECTION_CLOSED:
        out_comma();
        out_uint("bytes_sent", net->tcp.close.bytes_sent);

        out_comma();
        out_uint("bytes_received", net->tcp.close.bytes_received);
        break;
    }

    out_object_end();
}

static void out_network_event(const char *name, struct ebpf_net_event *evt)
{
    out_object_start();
    out_event_type(name);
    out_comma();

    out_pid_info("pids", &evt->pids);
    out_comma();

    out_net_info("net", evt);
    out_comma();

    out_string("comm", (const char *)&evt->comm);

    out_object_end();
    out_newline();
}

static void out_network_connection_accepted_event(struct ebpf_net_event *evt)
{
    out_network_event("NETWORK_CONNECTION_ACCEPTED", evt);
}

static void out_network_connection_attempted_event(struct ebpf_net_event *evt)
{
    out_network_event("NETWORK_CONNECTION_ATTEMPTED", evt);
}

static void out_network_connection_closed_event(struct ebpf_net_event *evt)
{
    out_network_event("NETWORK_CONNECTION_CLOSED", evt);
}

static int event_ctx_callback(struct ebpf_event_header *evt_hdr)
{
    switch (evt_hdr->type) {
    case EBPF_EVENT_PROCESS_FORK:
        out_process_fork((struct ebpf_process_fork_event *)evt_hdr);
        break;
    case EBPF_EVENT_PROCESS_EXEC:
        out_process_exec((struct ebpf_process_exec_event *)evt_hdr);
        break;
    case EBPF_EVENT_PROCESS_EXIT:
        out_process_exit((struct ebpf_process_exit_event *)evt_hdr);
        break;
    case EBPF_EVENT_PROCESS_SETSID:
        out_process_setsid((struct ebpf_process_setsid_event *)evt_hdr);
        break;
    case EBPF_EVENT_PROCESS_SETUID:
        out_process_setuid((struct ebpf_process_setuid_event *)evt_hdr);
        break;
    case EBPF_EVENT_PROCESS_SETGID:
        out_process_setgid((struct ebpf_process_setgid_event *)evt_hdr);
        break;
    case EBPF_EVENT_PROCESS_TTY_WRITE:
        out_process_tty_write((struct ebpf_process_tty_write_event *)evt_hdr);
        break;
    case EBPF_EVENT_FILE_DELETE:
        out_file_delete((struct ebpf_file_delete_event *)evt_hdr);
        break;
    case EBPF_EVENT_FILE_CREATE:
        out_file_create((struct ebpf_file_create_event *)evt_hdr);
        break;
    case EBPF_EVENT_FILE_RENAME:
        out_file_rename((struct ebpf_file_rename_event *)evt_hdr);
        break;
    case EBPF_EVENT_NETWORK_CONNECTION_ACCEPTED:
        out_network_connection_accepted_event((struct ebpf_net_event *)evt_hdr);
        break;
    case EBPF_EVENT_NETWORK_CONNECTION_ATTEMPTED:
        out_network_connection_attempted_event((struct ebpf_net_event *)evt_hdr);
        break;
    case EBPF_EVENT_NETWORK_CONNECTION_CLOSED:
        out_network_connection_closed_event((struct ebpf_net_event *)evt_hdr);
        break;
    }

    return 0;
}

int main(int argc, char **argv)
{
    int err                    = 0;
    struct ebpf_event_ctx *ctx = NULL;

    if (signal(SIGINT, sig_int) == SIG_ERR) {
        fprintf(stderr, "Failed to register SIGINT handler\n");
        goto out;
    }

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        goto out;

    struct rlimit lim;
    lim.rlim_cur = RLIM_INFINITY;
    lim.rlim_max = RLIM_INFINITY;
    err          = setrlimit(RLIMIT_MEMLOCK, &lim);
    if (err < 0) {
        fprintf(stderr, "Could not set RLIMIT_MEMLOCK: %d %s\n", err, strerror(-err));
        goto out;
    }

    if (g_unbuffer_stdout) {
        err = setvbuf(stdout, NULL, _IONBF, 0);
        if (err < 0) {
            fprintf(stderr, "Could not turn off stdout buffering: %d %s\n", err, strerror(err));
            goto out;
        }
    }

    if (g_libbpf_verbose)
        ebpf_set_verbose_logging();

    struct ebpf_event_ctx_opts opts = {.events              = g_events_env,
                                       .features            = g_features_env,
                                       .features_autodetect = g_features_autodetect};

    err = ebpf_event_ctx__new(&ctx, event_ctx_callback, opts);

    if (err < 0) {
        fprintf(stderr, "Could not create event context: %d %s\n", err, strerror(-err));
        goto out;
    }

    if (g_print_initialized) {
        printf("{ \"eventstrace_message\": \"probes initialized\"}\n");
    }
    while (!exiting) {
        err = ebpf_event_ctx__next(ctx, 10);
        if (err < 0) {
            fprintf(stderr, "Failed to poll event context\n");
            break;
        }
    }

    ebpf_event_ctx__destroy(&ctx);

out:
    return err != 0;
}
