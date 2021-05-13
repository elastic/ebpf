/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under one
 * or more contributor license agreements. Licensed under the Elastic License 2.0;
 * you may not use this file except in compliance with the Elastic License 2.0.
 */


//
// Host Isolation - tool for updating map of allowed IPs and pids
//

/**
 * @brief Add a single IP to the IP allowlist
 *
 * @param[in] IPaddr IP address in uint format
 * @return Error value (0 for success)
 */
int
ebpf_map_allowed_IPs_add(uint32_t IPaddr);

/**
 * @brief Add a single PID (process ID) to the PID allowlist
 *
 * @param[in] pid PID number
 * @return Error value (0 for success)
 */
int
ebpf_map_allowed_pids_add(uint32_t pid);
