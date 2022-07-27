// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#ifndef EBPF_UPDATE_MAPS_H
#define EBPF_UPDATE_MAPS_H

#include <stdint.h>

//
// Host Isolation - tool for updating maps of allowed IPs, subnets and pids
//

/**
 * @brief Add a single IP to the IP allowlist
 *
 * @param[in] IPaddr IP address in uint format
 * @return Error value (0 for success)
 */
int ebpf_map_allowed_IPs_add(uint32_t IPaddr);

/**
 * @brief Delete a single IP from the IP allowlist
 *
 * @param[in] IPaddr IP address in uint format
 * @return Error value (0 for success)
 */
int ebpf_map_allowed_IPs_delete(uint32_t IPaddr);

/**
 * @brief Add an IP subnet to the subnet allowlist
 *
 * @param[in] IPaddr IP address in uint format
 * @param[in] netmask subnet mask in uint format (0-32)
 * @return Error value (0 for success)
 */
int ebpf_map_allowed_subnets_add(uint32_t IPaddr, uint32_t netmask);

/**
 * @brief Delete an IP subnet from the subnet allowlist
 *
 * @param[in] IPaddr IP address in uint format
 * @param[in] netmask subnet mask in uint format (0-32)
 * @return Error value (0 for success)
 */
int ebpf_map_allowed_subnets_delete(uint32_t IPaddr, uint32_t netmask);

/**
 * @brief Add a single PID (process ID) to the PID allowlist
 *
 * @param[in] pid PID number
 * @return Error value (0 for success)
 */
int ebpf_map_allowed_pids_add(uint32_t pid);

/**
 * @brief Delete a single PID (process ID) from the PID allowlist
 *
 * @param[in] pid PID number
 * @return Error value (0 for success)
 */
int ebpf_map_allowed_pids_delete(uint32_t pid);

/**
 * @brief Clear IP allowlist
 *
 * @return Error value (0 for success)
 */
int ebpf_map_allowed_IPs_clear();

/**
 * @brief Clear IP subnet allowlist
 *
 * @return Error value (0 for success)
 */
int ebpf_map_allowed_subnets_clear();

/**
 * @brief Clear pid allowlist
 *
 * @return Error value (0 for success)
 */
int ebpf_map_allowed_pids_clear();
#endif
