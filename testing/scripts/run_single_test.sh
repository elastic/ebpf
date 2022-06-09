#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0

set -x

# Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
# one or more contributor license agreements. Licensed under the Elastic
# License 2.0; you may not use this file except in compliance with the Elastic
# License 2.0.

# Runs a BPF test on a single kernel.
# Usage ./run_single_test.sh <kernel bzImage> <kernel initramfs> <kernel name> <results file>

# This script is invoked by run_tests.sh, the testrunning logic is in its own
# script to make it easy to pass a bunch of ./run_single_test.sh commands
# to GNU parallel in order to parallelize testrunning (which is much harder
# if this logic was in a bash function)

if [[ $# -ne 3 ]]
then
    echo "Usage: ${0} <arch> <kernel image> <results file>"
    exit 1
fi

ARCH=$1
KERNEL=$2
RESULTS_FILE=$3
SUCCESS_STRING="ALL BPF TESTS PASSED"

HOST_ARCH=$(uname -m)
if [[ -e /dev/kvm ]]
then
    # KVM is available, see if we can use it
    if [[ $HOST_ARCH == "x86_64" && $ARCH == "x86_64" ]]  || [[ $HOST_ARCH == "arm64" && $ARCH == "aarch64" ]]
    then
        # Enable KVM if we have it and host/guest arches match
        EXTRA_ARGS+=" -enable-kvm -cpu host"
    fi
fi

if [[ $ARCH == "aarch64" ]]
then
	# qemu-system-aarch64 requires you to pass a -machine, just use -M virt
	# for a generic aarch64 machine (we don't care about hardware specifics)
	EXTRA_ARGS+=" -M virt"

	# aarch64 uses ttyAMA0 for the first serial port
	EXTRA_ARGS+=' -append "console=ttyAMA0"'

	# Need to specify a cpu for aarch64
	EXTRA_ARGS+=" -cpu cortex-a57"
elif [[ $ARCH == "x86_64" ]]
then
	# x86_64 uses ttyS0 for the first serial port
	EXTRA_ARGS+=' -append "console=ttyS0"'
fi

qemu-system-${ARCH} \
    -nographic -m 1G \
    -kernel $KERNEL \
    -initrd initramfs-${ARCH}.cpio \
    $EXTRA_ARGS > $RESULTS_FILE &

# QEMU ignores SIGINT and just about everything else, run it in the
# background so we can ctrl-C out of the script
QEMU_PID=$!
trap "kill $QEMU_PID && exit 1" SIGINT
wait $!
trap - SIGINT

grep "$SUCCESS_STRING" $RESULTS_FILE > /dev/null
if [[ $? -eq 0 ]]
then
    echo "[PASS] $KERNEL"
else
    echo "[FAIL] $KERNEL"
fi
