// SPDX-License-Identifier: Elastic-2.0

/*
 * Copyright 2021 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
 * one or more contributor license agreements. Licensed under the Elastic
 * License 2.0; you may not use this file except in compliance with the Elastic
 * License 2.0.
 */

#include <stdio.h>

#include <LibEbpfEvents.h>

static void print_features(uint64_t features)
{
    printf("features: ");
    if (features & EBPF_FEATURE_BPF_TRAMP)
        printf("bpf_tramp,");
    printf("\n");
}

static void test_with(uint64_t features)
{
    if (ebpf_event_ctx__new(NULL, NULL, features, 0)) {
        printf("probe could not load with ");
        goto out;
    }
    printf("probe did load successfully with ");
out:
    print_features(features);
}

int main(int argc, char **argv)
{
    test_with(EBPF_FEATURE_BPF_TRAMP);
    test_with(0);
    return 0;
}
