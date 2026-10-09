# Builder image for building the probes with clang, the way cilium/ebpf's bpf2go
# does for elastic/ebpfevents (make build BPF_COMPILER=clang). See
# testing/README.md. Unlike Dockerfile.builder (CentOS 7 + zig, which the
# released artifacts are built with), this image is only meant for testing the
# probes, so it uses a current Ubuntu with clang-18.
#
#   make container BPF_COMPILER=clang
#   make build package testbins BPF_COMPILER=clang

FROM docker.io/ubuntu:24.04
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    bmake \
    bpftool \
    build-essential \
    ca-certificates \
    clang-18 \
    cmake \
    file \
    groff-base \
    llvm-18 \
    m4 \
    python3 \
    wget \
    xz-utils \
    && rm -rf /var/lib/apt/lists/*

# cmake/modules/BPF.cmake runs a bare llvm-strip.
RUN ln -s /usr/bin/llvm-strip-18 /usr/local/bin/llvm-strip

# Kludge (same as Dockerfile.builder):
#  ld on newer toolsets only likes -soname=<value> format, and bmake's mk files
#  use -soname <value> format.
RUN sed -i -e 's/-soname /-soname=/g' /usr/share/mk/lib.mk

ENV NOCONTAINER=TRUE
ENV MAKESYSPATH=/usr/share/mk

LABEL org.opencontainers.image.source https://github.com/elastic/ebpf
