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
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/in.h>

#include <EbpfEvents.h>

const char *argp_program_bug_address = "https://github.com/elastic/ebpf/issues";
const char argp_program_doc[] =
    "CLI frontend for the Elastic ebpf events library\n"
    "\n"
    "Prints process, network and file events sourced from the Elastic ebpf events library\n"
    "\n"
    "USAGE: ./EventsTrace [--all|-a] [--file-delete] [--file-create] [--file-rename] "
    "[--file-modify]\n"
    "[--process-fork] [--process-exec] [--process-exit] [--process-setsid] [--process-setuid] "
    "[--process-setgid] [--process-tty-write]\n"
    "[--net-conn-accept] [--net-conn-attempt] [--net-conn-closed]\n"
    "[--print-features-on-init] [--unbuffer-stdout] [--libbpf-verbose]\n";

// Somewhat kludgy way of ensuring argp doesn't print the EBPF_* constants that
// happen to be valid ASCII values as short options. We pass these enum values
// to argp and start them at 0x80, so argp doesn't recognize them as valid
// ASCII and print them as short options.
enum cmdline_opts {
    // Events
    FILE_DELETE = 0x80,
    FILE_CREATE,
    FILE_RENAME,
    FILE_MODIFY,
    PROCESS_FORK,
    PROCESS_EXEC,
    PROCESS_EXIT,
    PROCESS_SETSID,
    PROCESS_SETUID,
    PROCESS_SETGID,
    PROCESS_TTY_WRITE,
    NETWORK_CONNECTION_ATTEMPTED,
    NETWORK_CONNECTION_ACCEPTED,
    NETWORK_CONNECTION_CLOSED,
    CMDLINE_MAX
};

static uint64_t cmdline_to_lib[CMDLINE_MAX] = {
// clang-format off
#define x(name) [name] = EBPF_EVENT_##name,
    x(FILE_DELETE)
    x(FILE_CREATE)
    x(FILE_RENAME)
    x(FILE_MODIFY)
    x(PROCESS_FORK)
    x(PROCESS_EXEC)
    x(PROCESS_EXIT)
    x(PROCESS_SETSID)
    x(PROCESS_SETUID)
    x(PROCESS_SETGID)
    x(PROCESS_TTY_WRITE)
    x(NETWORK_CONNECTION_ATTEMPTED)
    x(NETWORK_CONNECTION_ACCEPTED)
    x(NETWORK_CONNECTION_CLOSED)
#undef x
    // clang-format on
};

static const struct argp_option opts[] = {
    {"all", 'a', NULL, false, "Print all events", 0},
    {"file-delete", FILE_DELETE, NULL, false, "Print file delete events", 0},
    {"file-create", FILE_CREATE, NULL, false, "Print file create events", 0},
    {"file-rename", FILE_RENAME, NULL, false, "Print file rename events", 0},
    {"file-modify", FILE_MODIFY, NULL, false, "Print file modification events", 0},
    {"process-fork", PROCESS_FORK, NULL, false, "Print process fork events", 0},
    {"process-exec", PROCESS_EXEC, NULL, false, "Print process exec events", 0},
    {"process-exit", PROCESS_EXIT, NULL, false, "Print process exit events", 0},
    {"process-setsid", PROCESS_SETSID, NULL, false, "Print process setsid events", 0},
    {"process-setuid", PROCESS_SETUID, NULL, false, "Print process setuid events", 0},
    {"process-setgid", PROCESS_SETGID, NULL, false, "Print process setgid events", 0},
    {"process-tty-write", PROCESS_TTY_WRITE, NULL, false, "Print process tty-write events", 0},
    {"net-conn-accept", NETWORK_CONNECTION_ACCEPTED, NULL, false,
     "Print network connection accepted events", 0},
    {"net-conn-attempt", NETWORK_CONNECTION_ATTEMPTED, NULL, false,
     "Print network connection attempted events", 0},
    {"net-conn-closed", NETWORK_CONNECTION_CLOSED, NULL, false,
     "Print network connection closed events", 0},
    {"print-features-on-init", 'i', NULL, false,
     "Print a message with feature information when probes have been successfully loaded", 1},
    {"unbuffer-stdout", 'u', NULL, false, "Disable userspace stdout buffering", 2},
    {"libbpf-verbose", 'v', NULL, false, "Log verbose libbpf logs to stderr", 2},
    {},
};

uint64_t g_events_env   = 0;
uint64_t g_features_env = 0;

bool g_print_features_init = 0;
bool g_features_printed    = 0;
bool g_unbuffer_stdout     = 0;
bool g_libbpf_verbose      = 0;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
    case 'i':
        g_print_features_init = 1;
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
    case FILE_DELETE:
    case FILE_CREATE:
    case FILE_RENAME:
    case FILE_MODIFY:
    case PROCESS_FORK:
    case PROCESS_EXEC:
    case PROCESS_EXIT:
    case PROCESS_SETSID:
    case PROCESS_SETUID:
    case PROCESS_SETGID:
    case PROCESS_TTY_WRITE:
    case NETWORK_CONNECTION_ACCEPTED:
    case NETWORK_CONNECTION_ATTEMPTED:
    case NETWORK_CONNECTION_CLOSED:
        g_events_env |= cmdline_to_lib[key];
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
    if (exiting)
        return;

    exiting = 1;
    fprintf(stdout, "Received SIGINT, exiting...\n");
}

static void out_comma()
{
    printf(",");
}

static void out_newline()
{
    printf("\n");
}

static void out_array_start()
{
    printf("[");
}

static void out_array_end()
{
    printf("]");
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

static void out_octal(const char *name, const short unsigned value)
{
    printf("\"%s\":%o", name, value);
}

static void out_escaped_string(const char *value)
{
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
            printf("\\\"");
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
}

static void out_string(const char *name, const char *value)
{
    printf("\"%s\":\"", name);
    out_escaped_string(value);
    printf("\"");
}

static void out_tty_dev(const char *name, struct ebpf_tty_dev *tty_dev)
{
    printf("\"%s\":", name);
    out_object_start();
    out_int("major", tty_dev->major);
    out_comma();
    out_int("minor", tty_dev->minor);
    out_comma();
    out_int("winsize_rows", tty_dev->winsize.rows);
    out_comma();
    out_int("winsize_cols", tty_dev->winsize.cols);
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
    out_comma();
    printf("\"cap_permitted\": \"%lu\"", cred_info->cap_permitted);
    out_comma();
    printf("\"cap_effective\": \"%lu\"", cred_info->cap_effective);
    out_object_end();
}

static void out_file_info(const char *name, struct ebpf_file_info *finfo)
{
    printf("\"%s\":", name);
    out_object_start();

    switch (finfo->type) {
    case EBPF_FILE_TYPE_DIR:
        out_string("type", "DIR");
        break;
    case EBPF_FILE_TYPE_FILE:
        out_string("type", "FILE");
        break;
    case EBPF_FILE_TYPE_SYMLINK:
        out_string("type", "SYMLINK");
        break;
    case EBPF_FILE_TYPE_CHARACTER_DEVICE:
        out_string("type", "CHARACTER_DEVICE");
        break;
    case EBPF_FILE_TYPE_BLOCK_DEVICE:
        out_string("type", "BLOCK_DEVICE");
        break;
    case EBPF_FILE_TYPE_NAMED_PIPE:
        out_string("type", "NAMED_PIPE");
        break;
    case EBPF_FILE_TYPE_SOCKET:
        out_string("type", "SOCKET");
        break;
    case EBPF_FILE_TYPE_UNKNOWN:
        out_string("type", "UNKNOWN");
        break;
    }
    out_comma();

    out_uint("inode", finfo->inode);
    out_comma();

    out_octal("mode", finfo->mode);
    out_comma();

    out_uint("size", finfo->size);
    out_comma();

    out_int("uid", finfo->uid);
    out_comma();

    out_int("gid", finfo->gid);
    out_comma();

    out_uint("atime", finfo->atime);
    out_comma();

    out_uint("mtime", finfo->mtime);
    out_comma();

    out_uint("ctime", finfo->ctime);
    out_object_end();
}

static void out_null_delimited_string_array(const char *name, char *buf, size_t buf_size)
{
    // buf is an array (argv, env etc.) with multiple values delimited by a '\0'

    printf("\"%s\":", name);

    out_array_start();
    for (uint64_t index = 0; index < buf_size && buf_size != 1;) {
        char *elem = buf + index;
        printf(" \"");
        out_escaped_string(elem);
        printf("\"");
        index += (strlen(elem) + 1);
        if (index < buf_size - 1) {
            out_comma();
        } else {
            printf(" ");
        }
    }
    out_array_end();
}

static void out_file_delete(struct ebpf_file_delete_event *evt)
{
    out_object_start();
    out_event_type("FILE_DELETE");
    out_comma();

    out_pid_info("pids", &evt->pids);
    out_comma();

    out_int("mount_namespace", evt->mntns);
    out_comma();

    out_string("comm", (const char *)&evt->comm);
    out_comma();

    out_file_info("file_info", &evt->finfo);

    struct ebpf_varlen_field *field;
    FOR_EACH_VARLEN_FIELD(evt->vl_fields, field)
    {
        out_comma();
        switch (field->type) {
        case EBPF_VL_FIELD_PATH:
            out_string("path", field->data);
            break;
        case EBPF_VL_FIELD_SYMLINK_TARGET_PATH:
            out_string("symlink_target_path", field->data);
            break;
        default:
            fprintf(stderr, "Unexpected variable length field: %d\n", field->type);
            break;
        }
    }

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

    out_int("mount_namespace", evt->mntns);
    out_comma();

    out_string("comm", (const char *)&evt->comm);
    out_comma();

    out_file_info("file_info", &evt->finfo);

    struct ebpf_varlen_field *field;
    FOR_EACH_VARLEN_FIELD(evt->vl_fields, field)
    {
        out_comma();
        switch (field->type) {
        case EBPF_VL_FIELD_PATH:
            out_string("path", field->data);
            break;
        case EBPF_VL_FIELD_SYMLINK_TARGET_PATH:
            out_string("symlink_target_path", field->data);
            break;
        default:
            fprintf(stderr, "Unexpected variable length field: %d\n", field->type);
            break;
        }
    }

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

    out_int("mount_namespace", evt->mntns);
    out_comma();

    out_string("comm", (const char *)&evt->comm);
    out_comma();

    out_file_info("file_info", &evt->finfo);

    struct ebpf_varlen_field *field;
    FOR_EACH_VARLEN_FIELD(evt->vl_fields, field)
    {
        out_comma();
        switch (field->type) {
        case EBPF_VL_FIELD_OLD_PATH:
            out_string("old_path", field->data);
            break;
        case EBPF_VL_FIELD_NEW_PATH:
            out_string("new_path", field->data);
            break;
        case EBPF_VL_FIELD_SYMLINK_TARGET_PATH:
            out_string("symlink_target_path", field->data);
            break;
        default:
            fprintf(stderr, "Unexpected variable length field: %d\n", field->type);
            break;
        }
    }

    out_object_end();
    out_newline();
}

static void out_file_modify(struct ebpf_file_modify_event *evt)
{
    out_object_start();
    out_event_type("FILE_MODIFY");
    out_comma();

    out_pid_info("pids", &evt->pids);
    out_comma();

    out_int("mount_namespace", evt->mntns);
    out_comma();

    out_string("comm", (const char *)&evt->comm);
    out_comma();

    switch (evt->change_type) {
    case EBPF_FILE_CHANGE_TYPE_CONTENT:
        out_string("change_type", "CONTENT");
        break;
    case EBPF_FILE_CHANGE_TYPE_PERMISSIONS:
        out_string("change_type", "PERMISSIONS");
        break;
    case EBPF_FILE_CHANGE_TYPE_OWNER:
        out_string("change_type", "OWNER");
        break;
    case EBPF_FILE_CHANGE_TYPE_XATTRS:
        out_string("change_type", "XATTRS");
        break;
    default:
        fprintf(stderr, "Invalid change type: %d\n", evt->change_type);
        break;
    }
    out_comma();

    out_file_info("file_info", &evt->finfo);

    struct ebpf_varlen_field *field;
    FOR_EACH_VARLEN_FIELD(evt->vl_fields, field)
    {
        out_comma();
        switch (field->type) {
        case EBPF_VL_FIELD_PATH:
            out_string("path", field->data);
            break;
        case EBPF_VL_FIELD_SYMLINK_TARGET_PATH:
            out_string("symlink_target_path", field->data);
            break;
        default:
            fprintf(stderr, "Unexpected variable length field: %d\n", field->type);
            break;
        }
    }

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

    out_cred_info("creds", &evt->creds);

    struct ebpf_varlen_field *field;
    FOR_EACH_VARLEN_FIELD(evt->vl_fields, field)
    {
        out_comma();
        switch (field->type) {
        case EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH:
            out_string("pids_ss_cgroup_path", field->data);
            break;
        default:
            fprintf(stderr, "Unexpected variable length field: %d\n", field->type);
            break;
        }
    }

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

    struct ebpf_varlen_field *field;
    FOR_EACH_VARLEN_FIELD(evt->vl_fields, field)
    {
        out_comma();
        switch (field->type) {
        case EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH:
            out_string("pids_ss_cgroup_path", field->data);
            break;
        case EBPF_VL_FIELD_FILENAME:
            out_string("filename", field->data);
            break;
        case EBPF_VL_FIELD_CWD:
            out_string("cwd", field->data);
            break;
        case EBPF_VL_FIELD_ARGV:
            out_null_delimited_string_array("argv", field->data, field->size);
            break;
        case EBPF_VL_FIELD_ENV:
            out_null_delimited_string_array("env", field->data, field->size);
            break;
        default:
            fprintf(stderr, "Unexpected variable length field: %d\n", field->type);
            break;
        }
    }

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
    out_uint("tty_out_truncated", evt->tty_out_truncated);
    out_comma();
    out_tty_dev("tty", &evt->tty);
    out_comma();
    out_string("comm", (const char *)&evt->comm);

    struct ebpf_varlen_field *field;
    FOR_EACH_VARLEN_FIELD(evt->vl_fields, field)
    {
        out_comma();
        switch (field->type) {
        case EBPF_VL_FIELD_TTY_OUT:
            out_string("tty_out", field->data);
            break;
        default:
            fprintf(stderr, "Unexpected variable length field: %d\n", field->type);
            break;
        }
    }

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

    out_int("exit_code", evt->exit_code);

    struct ebpf_varlen_field *field;
    FOR_EACH_VARLEN_FIELD(evt->vl_fields, field)
    {
        out_comma();
        switch (field->type) {
        case EBPF_VL_FIELD_PIDS_SS_CGROUP_PATH:
            out_string("pids_ss_cgroup_path", field->data);
            break;
        default:
            fprintf(stderr, "Unexpected variable length field: %d\n", field->type);
            break;
        }
    }

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
    if (g_print_features_init)
        while (!g_features_printed)
            usleep(100000);

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
    case EBPF_EVENT_FILE_MODIFY:
        out_file_modify((struct ebpf_file_modify_event *)evt_hdr);
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

static void print_init_msg(uint64_t features)
{
    printf("{\"probes_initialized\": true, \"features\": {");
    printf("\"bpf_tramp\": %s", (features & EBPF_FEATURE_BPF_TRAMP) ? "true" : "false");
    printf("}}\n");
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

    if (g_unbuffer_stdout) {
        err = setvbuf(stdout, NULL, _IONBF, 0);
        if (err < 0) {
            fprintf(stderr, "Could not turn off stdout buffering: %d %s\n", err, strerror(err));
            goto out;
        }
    }

    if (g_libbpf_verbose)
        ebpf_set_verbose_logging();

    err = ebpf_event_ctx__new(&ctx, event_ctx_callback, g_events_env);
    if (err < 0) {
        fprintf(stderr, "Could not create event context: %d %s\n", err, strerror(-err));
        goto out;
    }

    if (g_print_features_init) {
        print_init_msg(ebpf_event_ctx__get_features(ctx));
        g_features_printed = 1;
    }

    while (!exiting) {
        err = ebpf_event_ctx__next(ctx, 10);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Failed to poll event context %d: %s\n", err, strerror(-err));
            break;
        }
    }

    ebpf_event_ctx__destroy(&ctx);

out:
    return err != 0;
}
