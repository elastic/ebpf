#!/usr/bin/env bash

SUMMARY_FILE="bpf-check-summary.txt"
RESULTS_DIR="results"
JOBS=$(nproc)

build_initramfs() {
    CPIO_OUT=$(pwd)/initramfs.cpio
    INITRAMFS_ROOT=$(mktemp -d)

    TEST_INFRA_DIR=$INITRAMFS_ROOT/test_infra
    mkdir -p $TEST_INFRA_DIR

    cp init/bin/init $INITRAMFS_ROOT

    cp test_bins/bin/* $TEST_INFRA_DIR
    cp testrunner/testrunner $TEST_INFRA_DIR
    cp ../build/non-GPL/EventsTrace/EventsTrace $TEST_INFRA_DIR

    pushd $INITRAMFS_ROOT
    find . | cpio --format=newc -ov > $CPIO_OUT
    popd

    rm -r $INITRAMFS_ROOT
}

build_init() {
    pushd init

    mkdir -p bin
    gcc -static init.c -o bin/init
    if [[ $? -ne 0 ]]
    then
        echo "Could not build init"
        exit 1
    fi

    popd
}

build_testrunner() {
    pushd testrunner > /dev/null
    go build

    if [[ $? -ne 0 ]]
    then
        echo "Could not build testrunner"
        exit 1
    fi
    popd > /dev/null
}

build_testbins() {
    pushd test_bins
    mkdir -p bin

    for C_SRC in *.c
    do
        BIN_NAME=bin/$(basename $C_SRC .c)

        gcc -static $C_SRC -o $BIN_NAME
        if [[ $? -ne 0 ]]
        then
            echo "Compilation of $C_SRC failed (see above)"
            exit 1
        fi
    done

    popd
}

test_on_custom_kernels() {
    FPATH=$1
    ROOT_UNPACK_DIR=$(mktemp -d /tmp/bpf-checker.XXXXXXXXXX)
    trap "rm -r $ROOT_UNPACK_DIR" SIGINT

    PARALLEL_CMDS=''
    DISTRO_PATHS=$(ls -d $FPATH/*)
    for DISTRO_PATH in $DISTRO_PATHS
    do
        DISTRO_NAME=$(basename $DISTRO_PATH)
        mkdir -p results/$(basename $DISTRO_NAME)

        KERNELS=$(ls -d $DISTRO_PATH/*)
        if [[ $? -ne 0 ]]
        then
            echo "Could not list kernels"
            exit 1
        fi

        DISTRO_UNPACK_DIR=$ROOT_UNPACK_DIR/$DISTRO_NAME
        mkdir -p $DISTRO_UNPACK_DIR
        for KERNEL_GS_PATH in $KERNELS
        do
            KERNEL_TARBALL=$(basename $KERNEL_GS_PATH)
            KERNEL_NAME=$(basename $KERNEL_GS_PATH .tar.gz)
            KERNEL_UNPACK_DIR=$DISTRO_UNPACK_DIR/$KERNEL_NAME
            RESULTS_FILE="results/$DISTRO_NAME/$KERNEL_NAME.txt"

            if ! [[ "$KERNEL_TARBALL" =~ ^5.(8|9|[1-9][0-9]) ]]
            then
                echo "[SKIP-OLD] $KERNEL_NAME"
                continue
            fi

            if ! [[ "$KERNEL_TARBALL" =~ (amd64|x86_64) ]]
            then
                echo "[SKIP-ARCH] $KERNEL_NAME"
                continue
            fi

            mkdir -p $KERNEL_UNPACK_DIR
            cp $KERNEL_GS_PATH $KERNEL_UNPACK_DIR > /dev/null 2>&1
            if [[ $? -ne 0 ]]
            then
                echo "Could not download kernel $KERNEL_GS_PATH to $KERNEL_UNPACK_DIR"
                exit 1
            fi

            tar -C $KERNEL_UNPACK_DIR -axvf $KERNEL_UNPACK_DIR/$KERNEL_TARBALL > /dev/null
            if [[ $? -ne 0 ]]
            then
                echo "Could not extract kernel $KERNEL"
                exit 1
            fi

            rm $KERNEL_UNPACK_DIR/$KERNEL_TARBALL

            PARALLEL_CMDS="${PARALLEL_CMDS}\n./scripts/run_single_test.sh $KERNEL_UNPACK_DIR/vmlinuz $KERNEL_NAME $RESULTS_FILE"
        done

        # All kernels collected for this distro, run tests and delete them
        N_KERNS=$(echo -ne $PARALLEL_CMDS | wc | awk '{ print $1 }')
        echo -e "\n$DISTRO_NAME ($N_KERNS kernel(s) to test)" >> $SUMMARY_FILE

        echo -e $PARALLEL_CMDS | parallel -k -j${JOBS} | tee -a $SUMMARY_FILE
        PARALLEL_CMDS=''

        rm -r $DISTRO_UNPACK_DIR
    done

    rm -r $ROOT_UNPACK_DIR
}

test_on_gs_kernels() {
    GS_BUCKET=$1
    ROOT_UNPACK_DIR=$(mktemp -d /tmp/bpf-checker.XXXXXXXXXX)
    trap "rm -r $ROOT_UNPACK_DIR" SIGINT

    PARALLEL_CMDS=''
    DISTRO_PATHS=$(gsutil ls $GS_BUCKET)
    for DISTRO_PATH in $DISTRO_PATHS
    do
        DISTRO_NAME=$(basename $DISTRO_PATH)
        mkdir -p results/$(basename $DISTRO_NAME)

        KERNELS=$(gsutil ls $DISTRO_PATH/)
        if [[ $? -ne 0 ]]
        then
            echo "Could not list kernels"
            exit 1
        fi

        DISTRO_UNPACK_DIR=$ROOT_UNPACK_DIR/$DISTRO_NAME
        mkdir -p $DISTRO_UNPACK_DIR
        for KERNEL_GS_PATH in $KERNELS
        do
            KERNEL_TARBALL=$(basename $KERNEL_GS_PATH)
            KERNEL_NAME=$(basename $KERNEL_GS_PATH .tar.gz)
            KERNEL_UNPACK_DIR=$DISTRO_UNPACK_DIR/$KERNEL_NAME
            RESULTS_FILE="results/$DISTRO_NAME/$KERNEL_NAME.txt"

            if ! [[ "$KERNEL_TARBALL" =~ ^5.(8|9|[1-9][0-9]) ]]
            then
                echo "[SKIP-OLD] $KERNEL_NAME"
                continue
            fi

            if ! [[ "$KERNEL_TARBALL" =~ (amd64|x86_64) ]]
            then
                echo "[SKIP-ARCH] $KERNEL_NAME"
                continue
            fi

            mkdir -p $KERNEL_UNPACK_DIR
            gsutil cp $KERNEL_GS_PATH $KERNEL_UNPACK_DIR > /dev/null 2>&1
            if [[ $? -ne 0 ]]
            then
                echo "Could not download kernel $KERNEL_GS_PATH to $KERNEL_UNPACK_DIR"
                exit 1
            fi

            tar -C $KERNEL_UNPACK_DIR -axvf $KERNEL_UNPACK_DIR/$KERNEL_TARBALL > /dev/null
            if [[ $? -ne 0 ]]
            then
                echo "Could not extract kernel $KERNEL"
                exit 1
            fi

            rm $KERNEL_UNPACK_DIR/$KERNEL_TARBALL

            PARALLEL_CMDS="${PARALLEL_CMDS}\n./scripts/run_single_test.sh $KERNEL_UNPACK_DIR/vmlinuz $KERNEL_NAME $RESULTS_FILE"
        done

        # All kernels collected for this distro, run tests and delete them
        N_KERNS=$(echo -ne $PARALLEL_CMDS | wc | awk '{ print $1 }')
        echo -e "\n$DISTRO_NAME ($N_KERNS kernel(s) to test)" >> $SUMMARY_FILE
        echo -e $PARALLEL_CMDS | parallel -k -j${JOBS} | tee -a $SUMMARY_FILE
        PARALLEL_CMDS=''

        rm -r $DISTRO_UNPACK_DIR
    done

    rm -r $ROOT_UNPACK_DIR
}

test_on_mainline_kernels() {
    mkdir -p $RESULTS_DIR/mainline
    PARALLEL_CMDS=''

    tar -axvf mainline-kernels.tar
    if [[ $? -ne 0 ]]
    then
        echo "Could not unpack mainline kernels"
        exit 1
    fi

    for KERNEL_IMAGE in $(ls mainline-kernels/* | sort -r -V)
    do
        IMAGE_BASENAME=$(basename $KERNEL_IMAGE)
        KERNEL_VER=${IMAGE_BASENAME#"bzImage-"}
        PARALLEL_CMDS="${PARALLEL_CMDS}\n./scripts/run_single_test.sh $KERNEL_IMAGE mainline-${KERNEL_VER} results/mainline/mainline-${KERNEL_VER}-results.out"
    done

    N_KERNS=$(echo -ne $PARALLEL_CMDS | wc | awk '{ print $1 }')
    echo -e "\nmainline ($N_KERNS kernel(s) to test)" >> $SUMMARY_FILE
    echo -e $PARALLEL_CMDS | parallel -k -j${JOBS} | tee -a $SUMMARY_FILE
}

test_setup() {
    build_init
    build_testrunner
    build_testbins
    build_initramfs

    mkdir -p $RESULTS_DIR
    echo "BPF check run at $(date)" > $SUMMARY_FILE
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
    echo "Usage: ./run_tests.sh [-m] [-d gs_bucket] [-c path] [-j jobs]"
    echo "-m          -- Test on mainline kernels located at mainlin-kernels.tar"
    echo "-c          -- Test on custom kernels located at given path"
    echo "-d <bucket> -- Test on distro kernels located in the given GCS bucket"
    echo "-j <jobs>   -- Spin up jobs VMs in parallel"
}

MAINLINE=0
DISTRO=0
CUSTOM=0
GS_BUCKET=""
while getopts ":mdc:j:" opt
do
    case ${opt} in
        m ) MAINLINE=1
            ;;
        d ) DISTRO=1
            GS_BUCKET=$OPTARG
            if [[ $GS_BUCKET != gs://* ]]
            then
                usage
                exit 1
            fi
            ;;
        c ) CUSTOM=1
            FPATH=$OPTARG
            if [[ $FPATH != /* ]]
            then
                usage
                exit 1
            fi
            ;;
        j ) JOBS=$OPTARG
            ;;
        \? )
            usage
            exit 1
            ;;
    esac
done

if [[ $MAINLINE == 0 && $DISTRO == 0 && $CUSTOM == 0 ]]
then
    echo "Specify -m and/or -d for mainline/distro kernels and/or -c for custom path"
    exit 1
fi

check_kvm
test_setup

if [[ $MAINLINE == 1 ]]
then
    test_on_mainline_kernels
fi

if [[ $DISTRO == 1 ]]
then
    test_on_gs_kernels $GS_BUCKET
fi

if [[ $CUSTOM == 1 ]]
then
    test_on_custom_kernels $FPATH
fi
