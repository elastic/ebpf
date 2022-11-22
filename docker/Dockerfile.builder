ARG SCRATCH=/misc/scratch

# Stage 1: Build static bpftool
# This step is required specifically to maintain support for
# centos7. bpftool is available on newer distros via package
# manager, but elastic/ebpf is built on centos7 to workaround
# glibc's unsupported backwards-compatibility. Here, we build
# a static bpftool on a newer ubuntu and copy it to centos7
# builder image to generate skeleton headers.

FROM docker.io/ubuntu:jammy as bpftool-builder
ARG SCRATCH
ENV DEBIAN_FRONTEND=noninteractive

RUN mkdir -p $SCRATCH
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
    ca-certificates \
    gcc \
    libelf-dev \
    libz-dev \
    make \
    openssl \
    python3 \
    wget

RUN mkdir -p $SCRATCH/kernel \
    && wget -qO- https://github.com/torvalds/linux/archive/refs/tags/v5.18.tar.gz | tar --strip-components=1 -xz -C $SCRATCH/kernel
RUN CFLAGS=-static make -C $SCRATCH/kernel/tools/bpf/bpftool


# Stage 2: Centos 7 ebpf-builder
FROM docker.io/centos:7 as ebpf-builder
ARG SCRATCH
RUN mkdir -p $SCRATCH

COPY --from=bpftool-builder $SCRATCH/kernel/tools/bpf/bpftool/bpftool /usr/local/bin/bpftool

RUN yum install -y centos-release-scl-rh epel-release
RUN yum upgrade -y
RUN yum install -y binutils \
    file \
    glibc-static \
    groff-base \
    llvm-toolset-7.0-llvm \
    m4 \
    make \
    devtoolset-10* \
    rh-python38 \
    wget \
    which \
    xz

RUN mkdir -p $SCRATCH/bmake/src \
    && wget -qO- "https://github.com/arichardson/bmake/tarball/master" | tar --strip-components=1 -xz -C $SCRATCH/bmake/src

RUN cd $SCRATCH/bmake/src \
    && CFLAGS="${CFLAGS} -DLIBBSD_OVERLAY -I/usr/include/bsd" ./boot-strap --install-prefix=/usr --install-host-target
RUN cd $SCRATCH/bmake/src \
    && ./boot-strap op=install --install-prefix=/usr \
    && rm -rf $SCRATCH/bmake

# Kludge:
#  ld on newer toolsets only likes -soname=<value> format, and bmake's mk files
#  use -soname <value> format.
RUN sed -i -e 's/-soname /-soname=/g' /usr/share/mk/lib.mk

RUN wget -qO- "https://cmake.org/files/v3.22/cmake-3.22.2-linux-`arch`.tar.gz" | tar --strip-components=1 -xz -C /usr

# Instead of building newer LLVM/CLANG for bpf, use Zig! 'zig cc[++]' is a drop-in
# replacement for clang[++]
RUN wget -qO- "https://ziglang.org/download/0.9.1/zig-linux-`arch`-0.9.1.tar.xz" \
    | tar -xJ --strip-components=1 -C /usr/local \
    && mv /usr/local/zig /usr/local/bin/zig

# Alas, zig doesn't package llvm-strip. But we don't need a new version of llvm-strip!
# Use the latest one available from package manager.
RUN printf "#!/bin/bash\nsource scl_source enable llvm-toolset-7.0\nexec llvm-strip \"\$@\"\n" > /usr/bin/llvm-strip \
    && chmod a+x /usr/bin/llvm-strip

RUN printf "#!/bin/bash\nsource scl_source enable rh-python38\nexec python3 \"\$@\"\n" > /usr/bin/python3 \
    && chmod a+x /usr/bin/python3
RUN printf "#!/bin/bash\nsource scl_source enable rh-python38\nexec pip3 \"\$@\"\n" > /usr/bin/pip3 \
    && chmod a+x /usr/bin/pip3

# Install clang-format. Anything to not build/maintain clang/llvm.
RUN python3 -m pip install --no-cache --upgrade pip clang-format==14.0.6

RUN printf "#!/bin/bash\nsource scl_source enable rh-python38\nexec clang-format \"\$@\"\n" > /usr/bin/clang-format \
    && chmod a+x /usr/bin/clang-format

# Create symlinks to avoid managing paths
RUN printf "#!/bin/bash\nsource scl_source enable devtoolset-10\nexec gcc \"\$@\"\n" > /usr/bin/`arch`-linux-gnu-gcc
RUN printf "#!/bin/bash\nsource scl_source enable devtoolset-10\nexec g++ \"\$@\"\n" > /usr/bin/`arch`-linux-gnu-g++
RUN printf "#!/bin/bash\nsource scl_source enable devtoolset-10\nexec ar \"\$@\"\n" > /usr/bin/`arch`-linux-gnu-ar
RUN printf "#!/bin/bash\nsource scl_source enable devtoolset-10\nexec nm \"\$@\"\n" > /usr/bin/`arch`-linux-gnu-nm
RUN printf "#!/bin/bash\nsource scl_source enable devtoolset-10\nexec ranlib \"\$@\"\n" > /usr/bin/`arch`-linux-gnu-ranlib
RUN printf "#!/bin/bash\nsource scl_source enable devtoolset-10\nexec ld \"\$@\"\n" > /usr/bin/`arch`-linux-gnu-ld
RUN printf "#!/bin/bash\nsource scl_source enable devtoolset-10\nexec strip \"\$@\"\n" > /usr/bin/`arch`-linux-gnu-strip
RUN printf "#!/bin/bash\nsource scl_source enable devtoolset-10\nexec objcopy \"\$@\"\n" > /usr/bin/`arch`-linux-gnu-objcopy

RUN chmod a+x /usr/bin/*-linux-gnu-*

RUN rm -rf /usr/bin/gcc && ln -s /usr/bin/`arch`-linux-gnu-gcc /usr/bin/gcc
RUN rm -rf /usr/bin/g++ && ln -s /usr/bin/`arch`-linux-gnu-g++ /usr/bin/g++
RUN rm -rf /usr/bin/ar && ln -s /usr/bin/`arch`-linux-gnu-ar /usr/bin/ar
RUN rm -rf /usr/bin/nm && ln -s /usr/bin/`arch`-linux-gnu-nm /usr/bin/nm
RUN rm -rf /usr/bin/ranlib && ln -s /usr/bin/`arch`-linux-gnu-ranlib /usr/bin/ranlib
RUN rm -rf /usr/bin/strip && ln -s /usr/bin/`arch`-linux-gnu-strip /usr/bin/strip
RUN rm -rf /usr/bin/objcopy && ln -s /usr/bin/`arch`-linux-gnu-objcopy /usr/bin/objcopy

RUN rm -rf /usr/bin/ld && ln -s /usr/bin/`arch`-linux-gnu-ld /usr/bin/ld
RUN rm -rf /usr/bin/cc && ln -s /usr/bin/`arch`-linux-gnu-gcc /usr/bin/cc
RUN rm -rf /usr/bin/c++ && ln -s /usr/bin/`arch`-linux-gnu-g++ /usr/bin/c++


# Cleanup
RUN rm -rf $SCRATCH
RUN yum clean all
RUN rm -rf /var/log/*


# Finally, squash everything to merge overlapping fs layers

FROM scratch as squashed
COPY --from=ebpf-builder / /
ENV PATH="${PATH}:/usr/local/bin"
ENV NOCONTAINER=TRUE
ENV MAKESYSPATH=/usr/share/mk

LABEL org.opencontainers.image.source https://github.com/elastic/ebpf
