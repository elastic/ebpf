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
under `test_bins`. Upon kernel startup, the Bluebox-generated init process runs
`testrunner`, which spins up
[EventsTrace](https://github.com/elastic/ebpf/tree/main/non-GPL/EventsTrace),
and runs various test binaries, ensuring generated events are correct. This
process is repeated on several different kernels run in QEMU.

## Running Tests

Before running tests, you will need to have built all artifacts in the repo
with `make build ARCH=<arch>`, then package them with `make package`.

To run tests, you will need to have a directory containing all the kernel
images you want to test. Then invoke:

```
./run_tests.sh -a <architecture> <packaged artifacts directory> <kernel images>
```

`architecture` can be one of `aarch64` or `x86_64`. The default directory for
packaged artifacts is `artifacts-<arch>/package`, e.g.
`artifacts-x86_64/package`.

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

A dockerized setup is provided at `kernel_builder/` to build mainline kernel
images for the tester. See `kernel_builder/README.md` for usage instructions.

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

The setup at `kernel_builder/` enables all of these, so any mainline kernels
built with it should work fine in virtme. Distro kernels won't necessarily.
Check the `.config` for the kernel you're trying to debug if it isn't working
in virtme.

## Debugging a Test Kernel Image With GDB

Occasionally it's useful to attach a debugger to the kernel itself, to
determine the exact cause of a particular BPF failure. To do this, you'll need
a kernel _ELF binary_ (not a compressed image), _with_ debugging symbols.

To debug a kernel in this way, you'll first need to generate the test initramfs
for the architecture you're interested in. A wrapper around Bluebox is provided
at `scripts/gen_initramfs.sh` to do this:

```
./scripts/gen_initramfs.sh <arch> <path to EventsTrace binary> <output file>
```

Where `arch` is one of `x86_64` or `aarch64`.

Now you can run the tests for the kernel you're interested in in QEMU. A wrapper
script around QEMU is provided for this purpose at `scripts/invoke_qemu.sh`. Make
sure to pass the `-d` flag to instruct QEMU to wait for a debugger attach, for example,
on x86_64, the invocation looks like this:

```
./scripts/invoke_qemu.sh -d x86_64 <initramfs cpio archive> <kernel image>
```

Then, in another terminal, run `gdb` on your kernel ELF binary with debug
symbols (usually called `vmlinux`). Connect to QEMU with `target remote
localhost:1234` and  set your source search path to a locally-checked-out clone
of Linux that matches the kernel you're debugging with `dir
<path_to_linux_source>`.

At this point, you'll be able to set breakpoints and continue execution with
`c`. For example, to break at `bpf_prog_load` (the function called by `bpf(2)`
to load a BPF program), the whole process looks like this:

```
$ gdb -q ./vmlinux-x86_64-v5.18
Reading symbols from ./vmlinux-x86_64-v5.18...
(gdb) dir ~/linux
Source directories searched: /home/vagrant/linux:$cdir:$cwd
(gdb) b bpf_prog_load
Breakpoint 1 at 0xffffffff8118f190: file kernel/bpf/syscall.c, line 2210.
(gdb) target remote localhost:1234
Remote debugging using localhost:1234
0x000000000000fff0 in exception_stacks ()
(gdb) c
Continuing.

Breakpoint 1, bpf_prog_load (attr=attr@entry=0xffffc9000020fe58, uattr=...) at kernel/bpf/syscall.c:2210
2210    {
(gdb) l
2205
2206    /* last field in 'union bpf_attr' used by this command */
2207    #define BPF_PROG_LOAD_LAST_FIELD core_relo_rec_size
2208
2209    static int bpf_prog_load(union bpf_attr *attr, bpfptr_t uattr)
2210    {
2211            enum bpf_prog_type type = attr->prog_type;
2212            struct bpf_prog *prog, *dst_prog = NULL;
2213            struct btf *attach_btf = NULL;
2214            int err;
```

From here, you can e.g. make your way into the verifier entry point with a
breakpoint on `bpf_check`.

Breakpoints can also be set in userspace. Use `add-symbol-file` to inform GDB
about symbols in a binary compiled with debug info. Breakpoints can then be set
on those userspace symbols and code execution can be followed into the deepest
regions of the kernel from userspace code. As an example, here's how to break
at `main` of the `fork_exit` test binary.

```
(gdb) add-symbol-file test_bins/bin/x86_64/fork_exit
add symbol table from file "test_bins/bin/x86_64/fork_exit"
(y or n) y
Reading symbols from test_bins/bin/x86_64/fork_exit...
(gdb) b main
Breakpoint 1 at 0x401857: file fork_exit.c, line 18.
(gdb) c
Continuing.

Breakpoint 1, main () at fork_exit.c:18
18      {
(gdb) l
13      #include <unistd.h>
14
15      #include "common.h"
16
17      int main()
18      {
19          pid_t pid;
20          CHECK(pid = fork(), -1);
21
22          if (pid != 0) {
```
