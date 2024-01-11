#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0

# Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
# one or more contributor license agreements. Licensed under the Elastic
# License 2.0; you may not use this file except in compliance with the Elastic
# License 2.0.

readonly PROGNAME=$(basename $0)
readonly ARGS="$@"

file_exists() {
    [[ -e /dev/kvm ]]
}

is_empty() {
    [[ -z $1 ]]
}

exit_error() {
    echo "$1"
    exit 1
}

exit_usage() {
    cat <<EOF
Usage: $PROGNAME [-d] [-k] <arch> <initramfs> <kernel image>

Runs the given kernel image in a headless QEMU machine of the specified
arch (can be "x86_64" or "aarch64"), with the given initramfs CPIO archive.

OPTIONS:
    -d Wait for a debugger to attach before starting the VM
    -k Attempt to use KVM if available

EXAMPLE:
    $PROGNAME x86_64 initramfs-x86_64.cpio linux-image-v5.13
EOF
    exit 1
}

main() {
    local debug
    local kvm_requested
    while getopts "d" opt; do
        case ${opt} in
            d ) debug="1"
                ;;
            k ) kvm_requested="1"
                ;;
            \? )
                exit_usage
                ;;
        esac
    done
    shift $(( OPTIND - 1))

    local arch=$1
    local initramfs=$2
    local kernel=$3
    local host_arch=$(uname -m)

    is_empty $arch \
        && exit_usage

    is_empty $kernel \
        && exit_usage

    is_empty $initramfs \
        && exit_usage

    [[ $arch != "x86_64" && $arch != "aarch64" ]] \
        && exit_usage

    local extra_args=""
    local bootparams=""

    if [[ $debug == "1" ]]; then
        extra_args+="-s -S"
        bootparams+="nokaslr"
    fi

    file_exists /dev/kvm && [[ $host_arch == $arch ]] && [[ kvm_requested == "1" ]] \
        && extra_args+=" -enable-kvm -cpu host"

    if [[ $arch == "aarch64" ]]; then
        # qemu-system-aarch64 requires you to pass a -machine, just use -M virt
        # for a generic aarch64 machine (we don't care about hardware specifics)
        extra_args+=" -M virt"

        # Need to specify a cpu for aarch64
        extra_args+=" -cpu cortex-a57"

        # aarch64 uses ttyAMA0 for the first serial port
        bootparams+=" console=ttyAMA0"
    elif [[ $arch == "x86_64" ]]; then
        # x86_64 uses ttyS0 for the first serial port
        bootparams+=" console=ttyS0"
    fi

    qemu-system-${arch} \
        -nographic -m 1G \
        -smp 8 \
        -kernel $kernel \
        -initrd $initramfs \
        -append "$bootparams" \
        $extra_args &

    # QEMU ignores SIGINT and just about everything else, run it in the
    # background so we can ctrl-C out of the script
    local qemu_pid=$!
    trap "kill $qemu_pid && exit 1" SIGINT
    wait $qemu_pid
    trap - SIGINT

    return $ret
}

main $ARGS
