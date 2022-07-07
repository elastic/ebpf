# Elastic eBPF Multi-Kernel Tester

This directory contains infrastructure that allows us to run tests against our
BPF probes on multiple kernels.

BPF code is heavily subject to breakage when run on different kernels due to
changes to internal kernel data structures, BPF verifier changes, differences
in function inlining and changes to kernel function signatures, among other
things. Due to this, it's imperative that we test our BPF probes across a wide
variety of kernels and ensure that they load and work as expected on all of
them.

The code in this directory leverages
[Bluebox](https://github.com/florianl/bluebox) to generate an
[initramfs](https://www.kernel.org/doc/html/latest/filesystems/ramfs-rootfs-initramfs.html#what-is-initramfs)
containing our test runner binary and statically linked test binaries found
under `test_bins`. `testrunner` spins up
[EventsTrace](https://github.com/elastic/ebpf/tree/main/non-GPL/EventsTrace),
and runs various test binaries, ensuring generated events are correct. This
process is repeated on several different kernels run in QEMU.

## Running Tests

Before running tests, you will need to have built a statically-linked
`EventsTrace` binary. The `build` make target will do this by default for you
and output a statically-linked `EventsTrace` at
`artifacts-$(arch)/non-GPL/EventsTrace/EventsTrace`.

To run tests, you will need to have a directory containing all the kernel
images you want to test. Then invoke:

```
./run_tests.sh -a <architecture> -e <path to EventsTrace binary> <kernel images>
```

`architecture` can be one of `aarch64` or `x86_64`.

A summary of the test run will be output to `bpf-check-summary.txt`. Results
for individual kernels will be output to `results/<kernel_name>.txt`. This is a
dump of the VM's serial console output, which will contain all stdout/stderr
from the testrunner, which tries to dump verbose information in case of a test
failure.

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

## Building Kernels

A script is provided at `scripts/build_mainline_kernels.sh` to build mainline kernel images
for the tester. To use it, you first need a clone of Linux:

```
git clone git://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git
```

Then, invoke the script with:

```
sudo ./build_mainline_kernels.sh linux/
```

What architectures and kernels to build for can be controlled by way of
variables in the script. Note that building a bunch of kernels will take a long
time on anything that doesn't have a large number of cores. Spinning up a
powerful VM in your favorite cloud provider a quick way to do things.

## KVM

Running tests will be _much_ faster if you have KVM (hardware acceleration)
enabled. `./run_tests.sh` will check for KVM support and print a warning
if it's disabled.

If you're working inside a VM to begin with, you'll need to have nested
virtualization enabled for KVM to work. Note that nested virtualization on
Intel CPUs appears to be not much faster than software emulation unless your
CPU supports [VMCS
shadowing](https://forums.virtualbox.org/viewtopic.php?f=1&t=98708&p=478598#p478598).

## Getting a Shell in a Test Kernel Image

If a kernel fails the checker,
[virtme](https://git.kernel.org/pub/scm/utils/kernel/virtme/virtme.git) is an
easy way to quickly spin it up, get a shell and debug it. To run a misbehaving
kernel in virtme, first clone virtme:

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
kernels built with it should work fine in virtme. Distro kernels won't
necessarily. Check the `.config` for the kernel you're trying to debug if it
isn't working in virtme.

## Debugging a Test Kernel Image With GDB

Occasionally it's useful to attach a debugger to the kernel itself, to
determine the exact cause of a particular BPF failure. To do this, you'll need
a kernel _ELF binary_ (not a compressed image), _with_ debugging symbols. The
`build_mainline_kernels.sh` script will do this for you, putting the ELF
binaries with debug info at `mainline-kernels/binaries/` and the compressed
images at `mainline-kernels/images/`.

To debug a kernel in this way, first run it in QEMU, passing `-s -S` to tell
QEMU to wait for a debugger attach. See `scripts/run_single_test.sh` for how to
do this for the architecture you're interested in. Additionally, add `-append
"nokaslr"` which will disable kernel address space layout randomization (which
is required so that function addresses line up with the data in the binary).

On x86_64, for example, the invocation is:

```
qemu-system-x86_64 \
    -s -S \
    -nographic -m 1G \
    -kernel <kernel image> \
    -initrd <initramfs cpio archive> \
    -append "console=ttyS0" \
    -append "nokaslr"
```

Then, in another terminal, run `gdb` on your kernel ELF binary with debug
symbols (usually called `vmlinux`). Connect to QEMU with `target remote
localhost:1234` and  set your source search path to a locally-checked-out clone
of Linux that matches the kernel you're debugging with `dir
<path_to_linux_source>`.

At this point, you'll be able to set breakpoints and continue execution with
`c`. For example, to break at `start_kernel` (the main architecture-independent
entry point on Linux), the whole process looks like this:

```
$ gdb -q vmlinux
Reading symbols from vmlinux...
(gdb) dir linux
Source directories searched: /home/vagrant/ebpf/testing/linux:$cdir:$cwd
(gdb) target remote localhost:1234
Remote debugging using localhost:1234
0x000000000000fff0 in exception_stacks ()
(gdb) b start_kernel
Breakpoint 1 at 0xffffffff833c1b2b: file init/main.c, line 850.
(gdb) c
Continuing.

Breakpoint 1, start_kernel () at init/main.c:850
warning: Source file is more recent than executable.
850     {
(gdb) l
845     {
846             rest_init();
847     }
848
849     asmlinkage __visible void __init __no_sanitize_address start_kernel(void)
850     {
851             char *command_line;
852             char *after_dashes;
853
854             set_task_stack_end_magic(&init_task);
```
