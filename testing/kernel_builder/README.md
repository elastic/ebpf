# Mainline Kernel Builder

This directory contains a dockerized setup to build mainline kernels. It
fetches kernel sources from [cdn.kernel.org](https://cdn.kernel.org),
configures them in a manner suitable for the tester, and builds them.

The whole process is done in a docker image with all required dependencies.
To build the image, do:

```
make image
```

Then, to build all kernels, do:

```
make
```

Kernel images will be output under `kernels/bin`. The versions and architectures
to build can be controlled by way of the globals declared at the top of
`build.sh`, or overridden with space-separated lists:

```
make BUILD_ARCHES=x86_64 BUILD_VERSIONS="6.6 6.8"
```

The kernel source tree is deleted after each build. The installed UAPI headers
are kept under `kernels/headers/<arch>`. To keep each kernel's
`vmlinux` (the ELF with debug info that gdb needs, see `testing/README.md`),
set `KEEP_VMLINUX=1`. They are output under `kernels/vmlinux/<arch>`, and each
is hundreds of MB:

```
make BUILD_ARCHES=x86_64 BUILD_VERSIONS="6.15" KEEP_VMLINUX=1
```
