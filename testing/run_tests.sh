#!/usr/bin/env bash
set -x

SUMMARY_FILE="bpf-check-summary.txt"
RESULTS_DIR="results"
JOBS=$(nproc)

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

build_initramfs() {
    ARCH=$1
    EVENTSTRACE=$2

    build_testbins $ARCH
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
}

run_tests() {
    ARCH=$1
    DIR=$2

    mkdir -p results/

    PARALLEL_CMDS=''
    for KERNEL_IMAGE in $DIR/*
    do
        RESULTS_FILE="results/$(basename $KERNEL_IMAGE).txt"
        PARALLEL_CMDS="${PARALLEL_CMDS}\n./scripts/run_single_test.sh $ARCH $KERNEL_IMAGE $RESULTS_FILE"
    done

    N_KERNS=$(echo -ne $PARALLEL_CMDS | wc | awk '{ print $1 }')

    echo "Testing $N_KERNS $ARCH kernel(s) at $(date)" > $SUMMARY_FILE
    echo -e $PARALLEL_CMDS | parallel -k -j${JOBS} | tee -a $SUMMARY_FILE
}

check_kvm() {
    if ! [[ -e /dev/kvm ]]
    then
        echo "###########################################################"
        echo "# WARNING: /dev/kvm does not exist                        #"
        echo "# Tests will be fairly slow to execute                    #"
        echo "# You will have a much better experience with KVM enabled # "
        echo "###########################################################"
    fi
}

usage() {
    echo "Usage: ./run_tests.sh [-m] [-d gs_bucket] [-j jobs]"
    echo "-d <bucket> -- Test on distro kernels located in the given GCS bucket"
    echo "-j <jobs>   -- Spin up jobs VMs in parallel"
}

while getopts ":j:a:e:d:" opt
do
    case ${opt} in
        a ) ARCH=$OPTARG
            ;;
        e ) EVENTSTRACE=$OPTARG
            ;;
        d ) DIR=$OPTARG
            ;;
        j ) JOBS=$OPTARG
            ;;
        \? )
            usage
            exit 1
            ;;
    esac
done

if [[ -z $ARCH ]]
then
    echo "Architecture must be specified with -a <x86_64/aarch64>"
    exit 1
fi

if [[ -z $EVENTSTRACE ]]
then
    echo "EventsTrace binary must be provided with -e <path>"
    exit 1
fi

rm -rf $RESULTS_DIR
check_kvm
build_initramfs $ARCH $EVENTSTRACE

mkdir -p $RESULTS_DIR

run_tests $ARCH $DIR

grep "FAIL" $SUMMARY_FILE > /dev/null
if [[ $? -eq 0 ]]
then
    exit 1
else
    exit 0
fi
