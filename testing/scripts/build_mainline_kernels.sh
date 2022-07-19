#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0

# Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
# one or more contributor license agreements. Licensed under the Elastic
# License 2.0; you may not use this file except in compliance with the Elastic
# License 2.0.

# Builds kernels with the correct kconfigs to run on the multi-kernel test
# infrastructure. Kernels are built in a debian chroot (debootstrap must be
# installed) so the build environment is totally reproducable and no setup on
# the host system is required. Modify the ARCHES and KERNEL_VERSIONS variables
# in the kernel_builder.sh script output by this one to control which kernels
# are built.

readonly PROGNAME=$(basename $0)
readonly ARGS="$@"
set -x

output_kernel_builder() {
    cat <<"EOF" >$1
set -x
# Modify these to change what kernels we build
readonly ARCHES="x86_64 aarch64"
readonly BUILD_TAGS="v5.11 5.12"

config_kernel() {
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
    local arch=$1
    local tag=$2

    local make_arch
    local make_cc
    local output_file
    if [[ $arch == "x86_64" ]]
    then
        make_arch="x86_64"
        make_cc="x86_64-linux-gnu-"
        make_target="bzImage"
        output_file="arch/x86/boot/bzImage"
    elif [[ $arch == "aarch64" ]]
    then
        make_arch="arm64" # Linux uses "arm64", others use "aarch64", aargh
        make_cc="aarch64-linux-gnu-"
        make_target="Image"
        output_file="arch/arm64/boot/Image"
    fi

    make clean
    rm .config

    ARCH=${make_arch} make defconfig

    config_kernel

    yes | ARCH=${make_arch} make olddefconfig

    yes | ARCH=${make_arch} CROSS_COMPILE=${make_cc} make ${make_target} -j$(nproc)
    mv $output_file mainline-kernels/$arch/images/linux-image-${arch}-${tag}
    mv vmlinux mainline-kernels/$arch/debug_binaries/vmlinux-${arch}-${tag}
}

exit_error() {
    echo $1
    exit 1
}

install_packages() {
    dpkg --add-architecture arm64
    echo "deb http://deb.debian.org/debian bullseye-backports main" >> /etc/apt/sources.list
    apt-get -y update

    apt-get -y install \
        git gcc make libssl-dev bison flex bc libelf-dev python3 \
        gcc-aarch64-linux-gnu

    # We need pahole >= 1.22 due to a bug in BTF generation pre 1.22. The default
    # version in the buster repos is 1.20. Backports version is 1.22.
    apt-get -y -t bullseye-backports install dwarves
}

main() {
    install_packages
    cd linux

    local i=1
    local n_kerns=$(( $(echo $ARCHES | wc -w) * $(echo $BUILD_TAGS | wc -w) ))
    for arch in $ARCHES; do
        mkdir -p mainline-kernels/$arch/images
        mkdir -p mainline-kernels/$arch/debug_binaries

        for tag in $BUILD_TAGS; do
            echo "[BUILD $i/$n_kerns] $arch/$v"

            git checkout $tag \
                || echo "Could not checkout $tag (see above)"

            build_kernel $arch $tag
            i=$(($i + 1))
        done
    done
}

main
EOF
}

exit_error() {
    echo $1
    exit 1
}

is_empty() {
    [[ -z $1 ]]
}

exit_usage() {
    echo "usage"
    exit 1
}

main() {
    local kernel_src_dir=$1

    is_empty kernel_src_dir \
        && exit_usage

    [[ $EUID -ne 0 ]] \
        && exit_error "This script must be run as root (for chroot)"

    mkdir -p chroot

    sudo debootstrap --arch amd64 --variant=minbase bullseye chroot http://ftp.us.debian.org/debian/ \
        || exit_error "Could not bootstrap chroot"

    cp -r $kernel_src_dir chroot/linux
    output_kernel_builder ./chroot/kernel_builder.sh
    chroot ./chroot /bin/bash /kernel_builder.sh
}

main $ARGS
