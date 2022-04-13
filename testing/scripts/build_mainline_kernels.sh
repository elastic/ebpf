#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0

# Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
# one or more contributor license agreements. Licensed under the Elastic
# License 2.0; you may not use this file except in compliance with the Elastic
# License 2.0.


# Builds images for every single mainline kernel we support (5.8+)

if [[ $# -ne 1 ]]
then
    echo "Usage ${0} <kernel source dir>"
    exit 1
fi

pushd $1

KERNEL_VERSIONS=$(git tag | egrep 'v5.(8|9|[1-9][0-9])(.[0-9]+$|$)' | sort -V)
N_KERNS=$(echo "$KERNEL_VERSIONS" | wc | awk '{ print $1 }')
I=1
mkdir -p mainline-kernels

for V in $KERNEL_VERSIONS
do
    echo "[BUILD $I/$N_KERNS] $V"
    git checkout $V
    make clean

    make defconfig

    # Enable BPF and force the JIT compiler (default on most distros)
    ./scripts/config \
        -e CONFIG_BPF_SYSCALL \
        -e CONFIG_BPF_JIT \
        -e CONFIG_BPF_JIT_ALWAYS_ON

    # Enable BTF
    ./scripts/config \
        -e CONFIG_DEBUG_INFO \
        -e CONFIG_DEBUG_INFO_BTF

     # Enable fentry/fexit's
    ./scripts/config \
        -e CONFIG_FUNCTION_TRACER

     # Enable /sys/kernel/debug/tracing/events/syscalls
    ./scripts/config \
        -e CONFIG_FTRACE_SYSCALLS \
        -e CONFIG_SECURITYFS

    # Virtio options required by virtme, so kernel can be debugged
    ./scripts/config \
        -e CONFIG_VIRTIO_PCI \
        -e CONFIG_NET_9P \
        -e CONFIG_NET_9P_VIRTIO \
        -e CONFIG_9P_FS \
        -e CONFIG_VIRTIO_NET \
        -e CONFIG_VIRTIO_CONSOLE \
        -e CONFIG_SCSI_VIRTIO

    # Overlayfs is needed for mount namespace tests
    ./scripts/config \
        -e CONFIG_OVERLAY_FS

    make olddefconfig

    make -j$(nproc)
    mv arch/x86/boot/bzImage mainline-kernels/bzImage-${V}
    I=$(($I + 1))
done

popd
