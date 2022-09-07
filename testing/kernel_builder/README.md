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

Kernel images will be output under `kenels/bin`. The versions and architectures
to build can be controlled by way of the globals declared at the top of
`build.sh`.
