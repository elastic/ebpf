#!/usr/bin/env bash

usage() {
    echo "Usage: ./gen_initramfs.sh <arch> <EventsTrace>"
    echo "where <arch> is one of x86_64 or aarch64"
}

build_testrunner() {
    pushd testrunner > /dev/null
    go clean
    GOARCH=$1 go build

    if [[ $? -ne 0 ]]
    then
        echo "Could not build testrunner"
        exit 1
    fi
    popd > /dev/null
}

build_testbins() {
    ARCH=$1
    pushd test_bins

    mkdir -p bin/$ARCH

    for C_SRC in *.c
    do
        BIN_PATH=bin/$ARCH/$(basename $C_SRC .c)

        ${ARCH}-linux-gnu-gcc -static $C_SRC -o $BIN_PATH
        if [[ $? -ne 0 ]]
        then
            echo "Compilation of $C_SRC for $ARCH failed (see above)"
            exit 1
        fi
    done

    popd
}

ARCH=$1
EVENTSTRACE=$2

if [[ -z $ARCH ]]
then
    usage
    exit 1
fi

if [[ -z $EVENTSTRACE ]]
then
    usage
    exit 1
fi

if [[ $ARCH == "aarch64" ]]
then
    # GCC uses "aarch64" as an identifier, golang uses "arm64"
    GOARCH="arm64"
elif [[ $ARCH == "x86_64" ]]
then
    # GCC uses "x86_64" as an identifier, golang uses "amd64"
    GOARCH="amd64"
fi

build_testrunner $GOARCH
build_testbins $ARCH

CMD="bluebox"
CMD+=" -a $GOARCH"
CMD+=" -e testrunner/testrunner"
CMD+=" -r $EVENTSTRACE"
CMD+=" -o initramfs-${ARCH}.cpio"
for BIN in test_bins/bin/$ARCH/*
do
    CMD+=" -r $BIN"
done

$CMD
if [[ $? -ne 0 ]]
then
    echo "Failed to generate initramfs"
    exit 1
fi
