// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

// Creates an IPv6 TCP listening socket, connects to it on the loopback
// interface, closes all sockets and exits. Used to test network connection
// events.

#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "common.h"

#define BOUND_PORT 2048

int dump_info(int client_port, int server_port)
{
    char pid_info[8192];
    gen_pid_info_json(pid_info, sizeof(pid_info));

    char netns[128];
    ssize_t nbytes;
    CHECK(nbytes = readlink("/proc/self/ns/net", netns, sizeof(netns)), -1);
    netns[nbytes] = '\0';

    uint64_t netns_inode;
    sscanf(netns, "net:[%lu]", &netns_inode);

    printf("{ \"pid_info\": %s, \"client_port\": %d, \"server_port\": %d, \"netns\": %lu }\n",
           pid_info, client_port, server_port, netns_inode);
}

int main()
{
    struct sockaddr_in6 serveraddr;
    struct sockaddr_in6 clientaddr;
    int listenfd;

    memset(&serveraddr, 0, sizeof(serveraddr));
    memset(&clientaddr, 0, sizeof(clientaddr));

    // socket() to create client socket
    int connectfd;
    CHECK(connectfd = socket(AF_INET6, SOCK_STREAM, 0), -1);

    // Ensure loopback interface is up
    //
    // Normally the loopback interface is brought up by the init process via
    // netlink or this equivalent ioctl but the init in our minimal VM setup
    // doesn't do this. Ensure loopback is up here or else the connect() call
    // below will fail with -ENETUNREACH.
    struct ifreq lo_up_req;
    strcpy(lo_up_req.ifr_name, "lo");
    CHECK(ioctl(connectfd, SIOCGIFFLAGS, &lo_up_req), -1);
    lo_up_req.ifr_flags |= IFF_UP;
    CHECK(ioctl(connectfd, SIOCSIFFLAGS, &lo_up_req), -1);

    // socket()/bind()/listen() to create a server socket
    serveraddr.sin6_family = AF_INET6;
    serveraddr.sin6_addr   = in6addr_any;
    serveraddr.sin6_port   = htons((unsigned short)BOUND_PORT);
    CHECK(listenfd = socket(AF_INET6, SOCK_STREAM, 0), -1);
    CHECK(setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)), -1);
    CHECK(bind(listenfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)), -1);
    CHECK(listen(listenfd, 1), -1);

    // connect() to connect to server socket
    clientaddr.sin6_family = AF_INET6;
    clientaddr.sin6_addr   = in6addr_loopback;
    clientaddr.sin6_port   = htons(BOUND_PORT);
    CHECK(connect(connectfd, (struct sockaddr *)&clientaddr, sizeof(clientaddr)), -1);

    // accept() on server socket
    int acceptfd;
    struct sockaddr_in6 acceptaddr;
    socklen_t sz = sizeof(acceptaddr);
    CHECK(acceptfd = accept(listenfd, (struct sockaddr *)&acceptaddr, &sz), -1);

    dump_info(ntohs(acceptaddr.sin6_port), BOUND_PORT);

    // The order of these two closes is important, see
    // comments in Go test code
    close(acceptfd);
    close(connectfd);

    close(listenfd);

    return 0;
}
