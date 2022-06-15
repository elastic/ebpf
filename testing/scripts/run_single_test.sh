#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0

# Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
# one or more contributor license agreements. Licensed under the Elastic
# License 2.0; you may not use this file except in compliance with the Elastic
# License 2.0.

# Runs a BPF test on a single kernel.
# Usage ./run_single_test.sh <kernel bzImage> <kernel name> <results file>

# This script is invoked by run_tests.sh, the testrunning logic is in its own
# script to make it easy to pass a bunch of ./run_single_test.sh commands
# to GNU parallel in order to parallelize testrunning (which is much harder
# if this logic was in a bash function)

if [[ $# -ne 3 ]]
then
    echo "Usage: ${0} <kernel bzImage> <kernel name> <results file>"
    exit 1
fi

KERNEL=$1
KERNEL_NAME=$2
RESULTS_FILE=$3
SUCCESS_STRING="ALL BPF TESTS PASSED"

KVM_ARGS=""
if [[ -e /dev/kvm ]]
then
    KVM_ARGS="-enable-kvm -cpu host"
fi

qemu-system-`arch` \
    -nographic -m 1G \
    -kernel $KERNEL \
    -initrd initramfs.cpio \
    -append "console=ttyS0" $KVM_ARGS > $RESULTS_FILE &

# QEMU ignores SIGINT and just about everything else, run it in the
# background so we can ctrl-C out of the script
QEMU_PID=$!
trap "kill $QEMU_PID && exit 1" SIGINT
wait $!
trap - SIGINT

grep "$SUCCESS_STRING" $RESULTS_FILE > /dev/null
if [[ $? -eq 0 ]]
then
    echo "[PASS] $KERNEL_NAME"
else
    echo "[FAIL] $KERNEL_NAME"
fi
