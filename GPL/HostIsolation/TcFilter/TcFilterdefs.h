// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause

/*
 * Copyright (C) 2021 Elasticsearch BV
 *
 * This software is dual-licensed under the BSD 2-Clause and GPL v2 licenses.
 * You may choose either one of them if you use this software.
 */

#ifndef TC_FILTERDEFS_H
#define TC_FILTERDEFS_H

#define PCKT_FRAGMENTED 65343

#define DROP_PACKET TC_ACT_SHOT
#define ALLOW_PACKET TC_ACT_UNSPEC

#define DNS_PORT (53)
#define DHCP_SERVER_PORT (67)
#define DHCP_CLIENT_PORT (68)

#endif // TC_FILTERDEFS_H
