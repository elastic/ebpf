#!/usr/bin/env bash
set -x

SUMMARY_FILE="bpf-check-summary.txt"
RESULTS_DIR="results"
JOBS=$(nproc)

run_tests() {
    ARCH=$1
    shift 1

    mkdir -p results/

    PARALLEL_CMDS=''
    for KERNEL_IMAGE in "$@"
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
    echo "Usage: ./run_tests.sh <-a arch> <-e EventsTrace> [-j jobs] <kernel images>"
    echo "-a <arch>        Arch to test, can be \"x86_64\" or \"aarch64\""
    echo "-k <kernels>     Paths to kernel images to test against"
    echo "-e <EventsTrace> Path to a statically-linked EventsTrace binary"
    echo "-j <jobs>        Spin up <jobs> VMs in parallel"
}

while getopts ":j:a:e:" OPT
do
    case ${OPT} in
        a ) ARCH=$OPTARG
            ;;
        e ) EVENTSTRACE=$OPTARG
            ;;
        j ) JOBS=$OPTARG
            ;;
        \? )
            usage
            exit 1
            ;;
    esac
done

shift $(( OPTIND - 1))

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

if [[ -z $* ]]
then
    echo "Kernel images to test must be provided"
    exit 1
fi

rm -rf $RESULTS_DIR
check_kvm

./scripts/gen_initramfs.sh $ARCH $EVENTSTRACE
if [[ $? -ne 0 ]]
then
    echo "Could not build initramfs (see above)"
    exit 1
fi

mkdir -p $RESULTS_DIR

run_tests $ARCH $@

grep "FAIL" $SUMMARY_FILE > /dev/null
if [[ $? -eq 0 ]]
then
    exit 1
else
    exit 0
fi
