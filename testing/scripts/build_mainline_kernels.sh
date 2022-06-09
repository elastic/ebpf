#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0

# Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
# one or more contributor license agreements. Licensed under the Elastic
# License 2.0; you may not use this file except in compliance with the Elastic
# License 2.0.

# Builds kernels with the correct kconfigs to run on the multi-kernel test infrastructure
# Architectures. Kernels are built in a debian chroot (debootstrap must be installed).
# Modify the ARCHES and KERNEL_VERSIONS variables in the kernel_builder script
# output by this one to control which kernels are built.

output_kernel_builder() {
    cat <<"EOF" >$1
set -x
config_common() {
     # Enable BPF and force the JIT compiler (default on most distros)
    ./scripts/config \
        -e CONFIG_BPF_SYSCALL \
        -e CONFIG_BPF_JIT \
        -e CONFIG_BPF_JIT_ALWAYS_ON

    # Enable BTF
    # NB: We need to specify DWARF4 as BTF is incompatible with DWARF5 as of v5.18
    # NB: BTF depends on CONFIG_DEBUG_INFO_REDUCED being _disabled_
    ./scripts/config \
        -e CONFIG_DEBUG_INFO \
        -e CONFIG_DEBUG_INFO_DWARF4 \
        -e CONFIG_DEBUG_INFO_BTF \
        -d CONFIG_DEBUG_INFO_REDUCED

     # Enable /sys/kernel/debug/tracing/events/syscalls
    ./scripts/config \
        -e CONFIG_FTRACE_SYSCALLS \
        -e CONFIG_SECURITYFS

    # Virtio options required by virtme, so we can use it to get a shell
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

    # Enable cgroups and all subsystems
    ./scripts/config \
        -e CONFIG_CGROUPS \
        -e CONFIG_BLK_CGROUP \
        -e CONFIG_CGROUP_SCHED \
        -e CONFIG_CGROUP_PIDS \
        -e CONFIG_CGROUP_RDMA \
        -e CONFIG_CGROUP_FREEZER \
        -e CONFIG_CGROUP_HUGETLB \
        -e CONFIG_CGROUP_DEVICE \
        -e CONFIG_CGROUP_CPUACCT \
        -e CONFIG_CGROUP_PERF \
        -e CONFIG_CGROUP_BPF \
        -e CONFIG_CGROUP_NET_PRIO \
        -e CONFIG_CGROUP_NET_CLASSID

    # Enable ftrace, needed for fentry/fexit bpf programs
    ./scripts/config \
        -e CONFIG_FTRACE \
        -e CONFIG_FUNCTION_TRACER

    # Need kprobes on aarch64 where fentry programs are not available
    ./scripts/config \
        -e CONFIG_KPROBES

    # Enable IPv6 (not on by default in aarch64 defconfig)
    # We attach to IPv6 functions to get network events
    ./scripts/config \
        -e CONFIG_IPV6

    # Enable taskstats (not on by default in aarch64 pre 5.18). This will
    # create a taskstats_exit function (which we hook).
    ./scripts/config \
        -e CONFIG_TASKSTATS
}


build_kernel() {
        ARCH=$1
        VERSION=$2

        if [[ $ARCH == "x86_64" ]]
        then
            MAKE_ARCH="x86_64"
            MAKE_CC="x86_64-linux-gnu-"
            MAKE_TARGET="bzImage"
            OUTPUT_FILE="arch/x86/boot/bzImage"
        elif [[ $ARCH == "aarch64" ]]
        then
            MAKE_ARCH="arm64" # Linux uses "arm64", others use "aarch64", aargh
            MAKE_CC="aarch64-linux-gnu-"
            MAKE_TARGET="Image"
            OUTPUT_FILE="arch/arm64/boot/Image"
        fi

		make clean
		rm .config

        ARCH=${MAKE_ARCH} make defconfig

        config_common

        yes | ARCH=${MAKE_ARCH} make olddefconfig

        yes | ARCH=${MAKE_ARCH} CROSS_COMPILE=${MAKE_CC} make ${MAKE_TARGET} -j$(nproc)
        mv $OUTPUT_FILE mainline-kernels/$ARCH/images/linux-image-${ARCH}-${VERSION}
        mv vmlinux mainline-kernels/$ARCH/debug_binaries/vmlinux-${ARCH}-${VERSION}
}

dpkg --add-architecture arm64
echo "deb http://deb.debian.org/debian bullseye-backports main" >> /etc/apt/sources.list
apt-get -y update

apt-get -y install \
    git gcc make libssl-dev bison flex bc libelf-dev python3 \
    gcc-aarch64-linux-gnu

# We need pahole >= 1.22 due to a bug in BTF generation pre 1.22. The default
# version in the buster repos is 1.20. Backports version is 1.22.
apt-get -y -t bullseye-backports install dwarves

# Modify these to change what kernels we build
ARCHES="x86_64 aarch64"
KERNEL_VERSIONS="v5.11"
N_KERNS=$(( $(echo $ARCHES | wc -w) * $(echo $KERNEL_VERSIONS | wc -w) ))

cd linux

I=1
for ARCH in $ARCHES
do
    mkdir -p mainline-kernels/$ARCH/images
    mkdir -p mainline-kernels/$ARCH/debug_binaries

    for V in $KERNEL_VERSIONS
    do
        echo "[BUILD $I/$N_KERNS] $ARCH/$V"

        git checkout $V
        if [[ $? -ne 0 ]]
        then
            echo "Could not checkout $V (see above)"
            exit 1
        fi

        build_kernel $ARCH $V
        I=$(($I + 1))
    done
done
EOF
}

if [[ $EUID -ne 0 ]]
then
    echo "This script must be run as root (for chroot)"
    exit 1
fi

if [[ $# -ne 1 ]]
then
    echo "Usage ${0} <kernel source dir>"
    exit 1
fi

mkdir -p chroot
sudo debootstrap --arch amd64 --variant=minbase bullseye chroot http://ftp.us.debian.org/debian/

cp -r $1 chroot
output_kernel_builder ./chroot/kernel_builder.sh
chroot ./chroot /bin/bash /kernel_builder.sh
