#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0

# Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
# one or more contributor license agreements. Licensed under the Elastic
# License 2.0; you may not use this file except in compliance with the Elastic
# License 2.0.

# Builds kernels with the correct kconfigs to run on the multi-kernel test
# infrastructure.

readonly KERNEL_OUTPUT_DIR="kernels"

readonly BUILD_ARCHES=(
    "aarch64"
    "x86_64"
)

# We hit every minor release here, and grab a number of different patch
# releases from each LTS series (e.g. 5.10, 5.15)
BUILD_VERSIONS_PAHOLE_120=(
   "5.10.16" # Oldest we support
   "5.10.130"
   "5.12"
   "5.15.133"
   "5.19"
   "6.0"
   "6.1.55"
   "6.1.106"
   "6.6.47"
   "6.10.6"
)

BUILD_VERSIONS_PAHOLE_SOURCE=(
   "6.1.106"
   "6.4.16"
   "6.6.47"
)

exit_error() {
    echo $1
    exit 1
}

build_kernel() {
    local arch=$1
    local src_dir=$2
    local dest=$3

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
    yes | ARCH=${make_arch} CROSS_COMPILE=${make_cc} make ${make_target} -j$(nproc)
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

    for arch in ${BUILD_ARCHES[@]}; do
        echo "BUILD ${arch}/${version}"
        mkdir -p ${KERNEL_OUTPUT_DIR}/bin/${arch}
        build_kernel \
            ${arch} \
            ${KERNEL_OUTPUT_DIR}/src/linux-${version} \
            ${KERNEL_OUTPUT_DIR}/bin/${arch}/linux-${arch}-${version}
    done
}

# Check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

main() {
    # Fetch all longterm stable kernel versions and build those kernels

    # Check if required commands exist
    if ! command_exists curl || ! command_exists jq; then
	echo "Error: This script requires 'curl' and 'jq'. Please install them and try again."
	exit 1
    fi

    # Fetch kernel.org releases json
    json_data=$(curl -s https://www.kernel.org/releases.json)

    # Extract the latest stable version
    latest_stable=$(echo "$json_data" | jq -r '.latest_stable.version')

    # Extract all longterm versions
    longterm_versions=$(echo "$json_data" | jq -r '.releases[] | select(.moniker == "longterm") | .version')

    # Combine stable and longterm versions
    kernel_versions=("$latest_stable" $longterm_versions)

    # Filter out old versions
    filtered_versions=$(printf '%s\n' "${kernel_versions[@]}" | grep -vE '^[45]')

    # Merge fetched versions into static arrays
    BUILD_VERSIONS_PAHOLE_120=($(echo "${BUILD_VERSIONS_PAHOLE_120[@]}" "$filtered_versions" | tr ' ' '\n' | sort | uniq))
    BUILD_VERSIONS_PAHOLE_SOURCE=($(echo "${BUILD_VERSIONS_PAHOLE_SOURCE[@]}" "$filtered_versions" | tr ' ' '\n' | sort | uniq))

    if [ "$(pahole --version)" = "v1.20" ]; then
        for version in "${BUILD_VERSIONS_PAHOLE_120[@]}"; do
            fetch_and_build $version
        done
    else
        for version in "${BUILD_VERSIONS_PAHOLE_SOURCE[@]}"; do
            fetch_and_build $version
        done
    fi
}

main
