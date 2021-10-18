// SPDX-License-Identifier: GPL-2.0

/*
 * Elastic eBPF
 * Copyright 2021 Elasticsearch BV
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <https://www.gnu.org/licenses/>.
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
