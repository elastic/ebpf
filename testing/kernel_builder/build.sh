#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0

# Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
# one or more contributor license agreements. Licensed under the Elastic
# License 2.0; you may not use this file except in compliance with the Elastic
# License 2.0.

# Builds kernels with the correct kconfigs to run on the multi-kernel test
# infrastructure.

readonly KERNEL_OUTPUT_DIR="kernels"

readonly DEFAULT_BUILD_ARCHES=(
    "aarch64"
    "x86_64"
)

# The BUILD_ARCHES and BUILD_VERSIONS environment variables (space separated)
# override the defaults, e.g.:
#   make BUILD_ARCHES=x86_64 BUILD_VERSIONS="6.6 6.8"
if [[ -n $BUILD_ARCHES ]]; then
    read -r -a ARCHES <<< "$BUILD_ARCHES"
else
    ARCHES=("${DEFAULT_BUILD_ARCHES[@]}")
fi
readonly ARCHES

# We hit every minor release here, and grab a number of different patch
# releases from each LTS series (e.g. 5.10, 5.15)
readonly BUILD_VERSIONS_PAHOLE_120=(
    "5.10.16" # Oldest we support
    "5.10.130"
    "5.11"
    "5.12"
    "5.13"
    "5.14"
    "5.15"
    "5.15.133"
    "5.16"
    "5.17"
    "5.18"
    "5.19"
    "6.0"
    "6.1"
    "6.1.55"
)

readonly BUILD_VERSIONS_PAHOLE_SOURCE=(
    "6.2"
    "6.3"
    "6.4"
    "6.4.16"
    "6.5"
    "6.6"  # LTS
    "6.8"  # Ubuntu 24.04
    "6.11" # Only release with inode.__i_atime / __i_mtime
    "6.12" # LTS, inode timestamps split into _sec / _nsec
    "6.14" # Last with kernfs_node.parent
    "6.15" # kernfs_node.parent renamed to __parent
    "6.17"
    "6.18"
    "6.19"
    "7.0"
)

exit_error() {
    echo $1
    exit 1
}

build_kernel() {
    local arch=$1
    local src_dir=$2
    local dest=$3
    local version=$4

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

    local customconfig=$PWD/config.custom

    pushd ${src_dir}
    ARCH=${make_arch} make defconfig
    cat $customconfig >> .config
    yes | ARCH=${make_arch} make olddefconfig
    yes | ARCH=${make_arch} CROSS_COMPILE=${make_cc} make -j$(nproc)
    yes | ARCH=${make_arch} CROSS_COMPILE=${make_cc} make ${make_target} -j$(nproc)
    yes | ARCH=${make_arch} CROSS_COMPILE=${make_cc} make modules_prepare -j$(nproc)
    yes | ARCH=${make_arch} CROSS_COMPILE=${make_cc} make vmlinux -j$(nproc)
    yes | ARCH=${make_arch} CROSS_COMPILE=${make_cc} make headers_install -j$(nproc) INSTALL_HDR_PATH=linux-headers-${version}-${make_arch}
    popd

    mv ${src_dir}/${output_file} ${dest}
}

fetch_and_build() {
    local version=$1
    local archive=${KERNEL_OUTPUT_DIR}/src/linux-${version}.tar.xz

    mkdir -p ${KERNEL_OUTPUT_DIR}/src/

    curl -L "https://cdn.kernel.org/pub/linux/kernel/v${version%%.*}.x/linux-${version}.tar.xz" -o "${archive}"
    tar -C $(dirname ${archive}) -axvf ${archive}
    rm ${archive}

    for arch in ${ARCHES[@]}; do
        echo "BUILD ${arch}/${version}"
        mkdir -p ${KERNEL_OUTPUT_DIR}/bin/${arch}
        build_kernel \
            ${arch} \
            ${KERNEL_OUTPUT_DIR}/src/linux-${version} \
            ${KERNEL_OUTPUT_DIR}/bin/${arch}/linux-${arch}-${version} \
            ${version}
    done

    # A built tree with debug info is several GB, only the image is needed
    rm -rf ${KERNEL_OUTPUT_DIR}/src/linux-${version}
}

main() {
    if [[ -n $BUILD_VERSIONS ]]; then
        for version in ${BUILD_VERSIONS}; do
            fetch_and_build $version
        done
    elif [ "$(pahole --version)" = "v1.20" ]; then
        for version in ${BUILD_VERSIONS_PAHOLE_120[@]}; do
            fetch_and_build $version
        done
    else
        for version in ${BUILD_VERSIONS_PAHOLE_SOURCE[@]}; do
            fetch_and_build $version
        done
    fi
}

main
