// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

// Creates an IPv4 TCP listening socket, connects to it on the loopback
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

int main()
{
    struct sockaddr_in serveraddr;
    struct sockaddr_in clientaddr;
    int listenfd;

    memset(&serveraddr, 0, sizeof(serveraddr));
    memset(&clientaddr, 0, sizeof(clientaddr));

    // socket() to create client socket
    int connectfd;
    CHECK(connectfd = socket(AF_INET, SOCK_STREAM, 0), -1);

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
    serveraddr.sin_family      = AF_INET;
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);
    serveraddr.sin_port        = htons((unsigned short)BOUND_PORT);
    CHECK(listenfd = socket(AF_INET, SOCK_STREAM, 0), -1);
    CHECK(setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &(int){1}, sizeof(int)), -1);
    CHECK(bind(listenfd, (struct sockaddr *)&serveraddr, sizeof(serveraddr)), -1);
    CHECK(listen(listenfd, 1), -1);

    // connect() to connect to server socket
    clientaddr.sin_family      = AF_INET;
    clientaddr.sin_addr.s_addr = inet_addr("127.0.0.1");
    clientaddr.sin_port        = htons(BOUND_PORT);
    CHECK(connect(connectfd, (struct sockaddr *)&clientaddr, sizeof(clientaddr)), -1);

    // accept() on server socket
    int acceptfd;
    struct sockaddr_in acceptaddr;
    socklen_t sz = sizeof(acceptaddr);
    CHECK(acceptfd = accept(listenfd, (struct sockaddr *)&acceptaddr, &sz), -1);

    dump_info(ntohs(acceptaddr.sin_port), BOUND_PORT);

    // The order of these two closes is important, must match the order in ebpf_test.go
    close(connectfd);
    close(acceptfd);

    close(listenfd);

    return 0;
}
