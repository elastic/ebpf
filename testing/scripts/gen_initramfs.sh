#!/usr/bin/env bash
# SPDX-License-Identifier: Elastic-2.0

# Copyright 2022 Elasticsearch B.V. and/or licensed to Elasticsearch B.V. under
# one or more contributor license agreements. Licensed under the Elastic
# License 2.0; you may not use this file except in compliance with the Elastic
# License 2.0.

readonly PROGNAME=$(basename $0)
readonly ARGS="$@"

is_empty() {
    [[ -z $1 ]]
}

exit_error() {
    echo $1
    exit 1
}

exit_usage() {
    cat <<- EOF
Usage: $PROGNAME <arch> <artifacts> <output file>

Generate an initramfs for use in a test run.

EXAMPLE:
    $PROGNAME x86_64 ../artifacts-x86_64 initramfs-x86_64.cpio
EOF

    exit 1
}

build_testrunner() {
    local goarch=$1

    pushd testrunner > /dev/null

    go clean
    GOARCH=$goarch go build

    if [[ $? -ne 0 ]]
    then
        echo "Could not build testrunner"
        exit 1
    fi
    popd > /dev/null
}

readonly BUILD_VERSIONS_PAHOLE_SOURCE=(
#    "6.2"
    "6.3"
#    "6.4"
#    "6.4.16"
#    "6.5"
)
readonly BUILD_ARCHES=(
#    "aarch64"
    "x86_64"
)

build_testbins() {
    local arch=$1
    pushd test_bins > /dev/null

    mkdir -p bin/$arch

    for c_src in *.c; do
        local bin_path=bin/$arch/$(basename $c_src .c)

        ${arch}-linux-gnu-gcc -g -static $c_src -o $bin_path \
            || exit_error "compilation of $c_src for $arch failed (see above)"
    done

#    cp simple-kmod/simple-kmod.ko bin/$arch

### MST
#
#    # Now, let's build the simple-kmod for all permutations
#    pushd simple-kmod > /dev/null
#
#    for version in "${BUILD_VERSIONS_PAHOLE_SOURCE[@]}"; do
#        for arch in "${BUILD_ARCHES[@]}"; do
#            # Modify the KVER variable to include the architecture
#            # Assuming the version needs to be suffixed with the architecture for the KVER variable
#            local kver="${version}-${arch}"
#
#            # Running make with the specific KVER and ARCH
#            make all KVER=$kver ARCH=$arch || exit_error "compilation of simple-kmod for KVER=$kver ARCH=$arch failed (see above)"
#
#            # Assuming you want to copy the .ko file to the bin directory with a specific naming convention
#            # For example, the output file might be named simple-kmod-6.2-aarch64.ko
#            # Adjust the cp command according to your output file naming from your make process
#            local output_ko="simple-kmod-${version}-${arch}.ko"
#            cp "simple-kmod.ko" "../test_bins/bin/$arch/$output_ko" || exit_error "copy of $output_ko to bin/$arch failed (see above)"
#        done
#    done
#
#    popd > /dev/null

###END

    popd > /dev/null

    # MST now we're in Ebpf/testing
    # copy .ko file to test_bins
    cp kernel_builder/kernels/bin/${arch}/*.ko test_bins/bin/${arch}/
}

invoke_bluebox() {
    local goarch=$1
    local artifacts=$2
    local output_file=$3

    local eventstrace="$artifacts/bin/EventsTrace"
    local tcfiltertests="$artifacts/bin/BPFTcFilterTests"
    local tcfilterbpf="$artifacts/probes/TcFilter.bpf.o"

    # Attempt to use common Go bin path of ~/go/bin if bluebox is not in $PATH
    which bluebox \
        || export PATH=~/go/bin:$PATH

    local cmd="bluebox"
    cmd+=" -a $goarch"
    cmd+=" -e testrunner/testrunner"
    cmd+=" -r $eventstrace"
    cmd+=" -r $tcfiltertests"
    cmd+=" -r $tcfilterbpf"
    cmd+=" -o $output_file"
    for bin in test_bins/bin/$arch/*; do
        cmd+=" -r $bin"
    done

    $cmd \
        || exit_error "failed to generate initramfs (see above)"
}

main() {
    local arch=$1
    local artifacts=$2
    local output_file=$3

    is_empty $arch \
        && exit_usage

    is_empty $artifacts \
        && exit_usage

    is_empty $output_file \
        && exit_usage

    local goarch
    if [[ $arch == "aarch64" ]]
    then
        # GCC uses "aarch64" as an identifier, golang uses "arm64"
        goarch="arm64"
    elif [[ $arch == "x86_64" ]]
    then
        # GCC uses "x86_64" as an identifier, golang uses "amd64"
        goarch="amd64"
    fi

    build_testrunner $goarch
    build_testbins $arch
    invoke_bluebox $goarch $artifacts $output_file

    return 0
}

main $ARGS
