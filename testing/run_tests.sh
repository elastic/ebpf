#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0

# Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
# one or more contributor license agreements. Licensed under the Elastic
# License 2.0; you may not use this file except in compliance with the Elastic
# License 2.0.
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
        if grep -q "$SUCCESS_STRING" $f; then
            echo "PASS: $kern" >> $SUMMARY_FILE
        else
            echo "FAIL: $kern" >> $SUMMARY_FILE
            echo "TEST OUTPUT"
            cat $f
        fi
    done
}

exit_usage() {
    cat <<- EOF
Usage: $PROGNAME [-j jobs] <arch> <artifacts package directory> <kernel images>

Perform a run of the BPF multi-kernel tester with the given kernel images on
the given arch, with the given artifacts directory and with the given kernel
images.

OPTIONS:
    -j <jobs>       Spin up <jobs> VMs in parallel (defaults to nproc)

EXAMPLE:
    $PROGNAME -j3 x86_64 ../artifacts-x86_64/package linux-v5.12 linux-v5.13 linux-v5.14
EOF

    exit 1
}

main() {
    local arch=$1
    local artifacts="$2"
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

    is_empty "$artifacts" \
        && exit_usage

    echo "Images are:"
    echo $*

    is_empty $* \
        && exit_usage

    local initramfs="initramfs-${arch}.cpio"
    ./scripts/gen_initramfs.sh $arch "$artifacts" "$initramfs" \
        || exit_error "Could not build initramfs (see above)"

    run_tests "$arch" "$initramfs" $jobs $@

    grep "FAIL:" $SUMMARY_FILE > /dev/null \
        && exit_error "Some tests failed, see results files"

    exit 0
}

main $ARGS
