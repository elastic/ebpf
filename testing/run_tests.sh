#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0

# Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
# one or more contributor license agreements. Licensed under the Elastic
# License 2.0; you may not use this file except in compliance with the Elastic
# License 2.0.
set -x
readonly PROGNAME=$(basename $0)
readonly ARGS="$@"

readonly SUCCESS_STRING="ALL BPF TESTS PASSED"
readonly SUMMARY_FILE="bpf-check-summary.txt"
readonly RESULTS_DIR="results"

file_exists() {
    [[ -f $1 ]]
}

is_empty() {
    [[ -z $1 ]]
}

exit_error() {
    echo "$1"
    exit 1
}

run_tests() {
    local arch=$1
    local initramfs=$2
    local jobs=$3
    shift 3

    rm -rf $RESULTS_DIR $SUMMARY_FILE
    mkdir -p $RESULTS_DIR

    parallel \
        -k -j${jobs} \
        ./scripts/invoke_qemu.sh $arch $initramfs {} ">" $RESULTS_DIR/{/}.txt ::: $@

    echo "BPF-check run for $# $arch kernel(s) at $(date)" > $SUMMARY_FILE
    for f in $RESULTS_DIR/*; do
        local kern=$(basename $f .txt)
        grep "$SUMMARY_STRING" $f \
            && echo "[PASS] $kern" >> $SUMMARY_FILE \
            || echo "[FAIL] $kern" >> $SUMMARY_FILE
    done
}

exit_usage() {
    cat <<- EOF
Usage: $PROGNAME [-j jobs] <arch> <EventsTrace> <kernel images>

Perform a run of the BPF multi-kernel tester with the given kernel images
on the given arch, with the given EventsTrace binary and with the given
kernel images.

OPTIONS:
    -j <jobs>       Spin up <jobs> VMs in parallel (defaults to nproc)

EXAMPLE:
    $PROGNAME -j3 x86_64 EventsTrace linux-v5.12 linux-v5.13 linux-v5.14
EOF

    exit 1
}

main() {
    local arch=$1
    local eventstrace=$2
    local jobs=$(nproc)

    while getopts "j:" opt; do
        case ${opt} in
            j ) jobs=$OPTARG
                shift 1
                ;;
            \? )
                exit_usage
                ;;
        esac
    done

    shift 2

    is_empty $arch \
        && exit_usage

    is_empty $eventstrace \
        && exit_usage

    echo "Images are:"
    echo $*

    is_empty $* \
        && exit_usage

    local initramfs="initramfs-${arch}.cpio"
    ./scripts/gen_initramfs.sh $arch $eventstrace $initramfs \
        || exit_error "Could not build initramfs (see above)"

    run_tests $arch $initramfs $jobs $@

    grep "FAIL" $SUMMARY_FILE > /dev/null \
        && exit_error "Some tests failed, see results files"

    exit 0
}

main $ARGS
