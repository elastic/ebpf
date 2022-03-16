# Elastic BPF Cross-Kernel Tester

This directory contains code to run tests against our BPF probes on a wide
range of distro-specific as well as mainline kernels.

BPF code is heavily subject to breakage when run on different kernels due to
changes to internal kernel data structures, BPF verifier changes, differences
in function inlining and changes to kernel function signatures, among other
things. Due to this, it's imperative that we test our BPF probes across a wide
variety of kernels and ensure that they load and work as expected on all of
them.

While spinning up a new kernel in a VM is a rather heavyweight operation, the
code in this directory attempts to do this in as lightweight a way as possible.

A kernel to be tested against is booted up in a QEMU VM and a simple `init` is
run (see init directory) that does the following:
1) Mounts a `tmpfs` over the
[`rootfs`](https://www.kernel.org/doc/Documentation/filesystems/ramfs-rootfs-initramfs.txt)
that exists by default on Linux boot and copies all test utilities to it. This
is necessary as some test binaries need to `pivot_root` to simulate performing
operations in a container, which is impossible if the current root filesystem
is a rootfs (see `man 2 pivot_root` --  this is a special case in the kernel)
2) Mounts a `/proc`, `/sys` and other pseudo filesystems required by the tests
and testrunner
3) Executes the `testrunner` binary, which actually runs the tests

Theoretically, all this logic could be contained in the Go testrunner binary,
but having a separate `init` for system setup and `testrunner` for test logic
separates concerns nicely.

The `testrunner` binary is written in Go (see the `testrunner` directory). It
starts
[EventsTrace](https://github.com/elastic/ebpf/tree/main/non-GPL/EventsTrace)
and runs various statically linked binaries passed into the VM by way of an
[initramfs](https://www.kernel.org/doc/html/latest/filesystems/ramfs-rootfs-initramfs.html#what-is-initramfs)
that generate events, which are then read by the testrunner and verified. This
ensures we don't need to waste time starting up userspace so we can test
against a large number of kernels quickly. See
[bluebox](https://github.com/florianl/bluebox) for a more general
implementation of this idea, that this checker was based on.

## Running tests

Before running tests, you will need to have built a *statically linked*
`EventsTrace` binary at `../build/non-GPL/EventsTrace/EventsTrace`. You can
ensure `EventsTrace` is statically linked by setting `BUILD_STATIC_EVENTSTRACE`
to `TRUE` with CMake.

Then, to run tests against distro-specific kernels in a GCS bucket, use:

```
./run_tests.sh -d <path to GCS bucket>
```

This will build an initramfs with all testing utilities, download kernels for
each distro we support to a temp directory, and run tests against each of them.

The GCS bucket must be organized as follows:

```
.
`-- <distro_name>
    `-- <kernel version>__<further identifiers>.tar.gz
```

`<kernel_version>` is self explanatory. `<further_identifiers>` can be any
further identifying information you want (e.g. hash of kernel `.config`).

A summary of results will be output to `bpf-check-summary.txt`, it will look
something like this:

```
BPF check run at Wed Mar 30 23:37:02 UTC 2022

amazonlinux2 (14 kernel(s) to test)
[FAIL] 5.10.102-99.473.amzn2.x86_64__0935484e5841bc500dea24692ee242c51513b5c8__06f8afb18db65cd79c2f51f767dfe
[FAIL] 5.10.29-27.126.amzn2.x86_64__27df3384aff1a84c3b22bb814071e58f3ece3a0c__d771f9633d047683d45c99488b2904
[FAIL] 5.10.29-27.128.amzn2.x86_64__750e9cfd8d1e105c452bc69a49ceaea9d1aec481__99983b608ea32959f6ad4954f0b6a3
[FAIL] 5.10.35-31.135.amzn2.x86_64__f86fe5894f52a53213f5ed303f1a6a33b187d308__6ff61f75dc79c8ffad837ef8b13217
[FAIL] 5.10.47-39.130.amzn2.x86_64__95eb2fcd20dd74fd68e8ede670d23990837421fb__313f15df7abce099b51048cba164c8
[FAIL] 5.10.50-44.131.amzn2.x86_64__b2ea7f761beae2348781d709f4b6f1f9a66bdd46__32a06c62494515529666f98ddf2bd2
[FAIL] 5.10.50-44.132.amzn2.x86_64__79c9f4a9cf36ba0af7692e9f52b26b50c5ec9fc1__018194457120233cc1980cc0cf3a11
[FAIL] 5.10.59-52.142.amzn2.x86_64__c31c3a29a6699fdc5dce5fe96d95002e31dc1231__6b739f73347b29afc07691cd7a49a5
[FAIL] 5.10.62-55.141.amzn2.x86_64__29b3e3bb8e935236486c5ad32eb068aa3758697b__8a2eda135e22111bbd45936d3890a5
[FAIL] 5.10.68-62.173.amzn2.x86_64__045389e1cf65bb550c9cb0715d0f3703cb142066__bd980fc2aff66525c97b0b73dc106b
[FAIL] 5.10.75-79.358.amzn2.x86_64__ed84f4433756b0be50e2df5f11c9ece47b6490bc__9dd164c6805c5007fae0d3431b1425
[FAIL] 5.10.82-83.359.amzn2.x86_64__a4621859aacdfc67667d4119663571f9eb74617f__bd8c779129574004ccaac007b004f7
[FAIL] 5.10.93-87.444.amzn2.x86_64__6500f29d401b1567e596b5d860746b9eadb681e1__053aa89e0f3f14e7d5634d47861b81
[FAIL] 5.10.96-90.460.amzn2.x86_64__f28c9920ec2db19be4a00efa1efa38b7fbb0233c__dc0acdcb7de8114c7bd33a017a9903

fedora (3 kernel(s) to test)
[PASS] 5.11.12-300.fc34.x86_64__b52ee37478f2a28e98104e9a65e837ca622ec2af__14848199a1de253bf1608d0b666a1b37a1
[PASS] 5.14.10-300.fc35.x86_64__64d04be860c0ee0d20803ad51013e4040dad7f53__ea2ccf2c6784b1a15f337e29f0acc169c2
[FAIL] 5.8.15-301.fc33.x86_64__8a921f5be2e3d24ca54dadc95b971238912bf83f__3149d75a764470ca972c0026f3de7dd47f8
```

Results for individual kernels will be output to
`results/<distro>/<kernel_name>.txt`. This is a dump of the VM's serial console
output, which will contain all stdout/stderr from init, and then the
testrunner, which tries to dump verbose information in case of a test failure.

To run tests against mainline kernels, you will first need a tar archive
containing all the mainline kernel images you want to test against.
`scripts/build_mainline_kernels.sh` will do this for you.

Once you have your mainline kernels built, put the archive in this directory
as `mainline-kernels.tar` and run:

```
./run_tests.sh -m
```

Like with distro-specific kernels, a summary will be output to
`bpf-check_summary.txt` and individual kernel results will be found in
`results/mainline`.

`run_tests.sh` will try to parallelize tests to the greatest extent possible,
it does this with [GNU Parallel](https://gnu.org/software/parallel/), which you
will need to have installed in order to run `./run-tests.sh`. On most distros,
`parallel` is in the repositories. To install on Ubuntu, just run:

```
sudo apt install parallel
```

By default `run_tests.sh` will pass `-j$(nproc)` to `parallel` (i.e. spin up as
many jobs as there are CPU cores). You can change this by passing
`-j <number of jobs>` to `run-tests.sh`.

## KVM

Running tests will be _much_ faster if you have KVM (hardware acceleration)
enabled. `./run_tests.sh` will check for KVM support and print a warning
if it's disabled.

If you're working inside a VM to begin with, you'll need to have nested
virtualization enabled for KVM to work. Note that nested virtualization on
Intel CPUs appears to be not much faster than software emulation unless your
CPU supports [VMCS
shadowing](https://forums.virtualbox.org/viewtopic.php?f=1&t=98708&p=478598#p478598).

## Debugging Kernels

If a kernel fails the checker,
[virtme](https://git.kernel.org/pub/scm/utils/kernel/virtme/virtme.git) is
usually the easiest way to quickly spin it up, get a shell and debug it. To
run a misbehaving kernel in virtme, first clone virtme:

```
git clone git://git.kernel.org/pub/scm/utils/kernel/virtme/virtme.git
```

Then run the kernel with:

```
./virtme/virtme-run --kimg <kernel image> --qemu-opts -m 1G -enable-kvm
```

This will fire up the kernel in QEMU, running bash as the init process, and
mounting your host's root FS (read only) as the guest's root FS.

Note that to run a kernel in virtme, it will need to have the following Kconfig
flags set:

```
CONFIG_VIRTIO
CONFIG_VIRTIO_PCI
CONFIG_NET_9P
CONFIG_NET_9P_VIRTIO
CONFIG_9P_FS
CONFIG_VIRTIO_NET
CONFIG_VIRTIO_CONSOLE
CONFIG_SCSI_VIRTIO
```

The `build_mainline_kernels.sh` script enables all of these, so any mainline
kernels built with it should work fine in virtme. Distro kernels should
generally have them all enabled, but won't necessarily. Check the `.config` for
the kernel you're trying to debug if it isn't working in virtme.
