FROM ubuntu:jammy

ENV LINUX_TOOLS_VERSION=5.15.0-33
ENV DEBIAN_FRONTEND=noninteractive

# https://askubuntu.com/a/1323570
#
# We need the aarch64 libz package. We need to add ports.ubuntu.com (the
# default repos don't have aarch64 packages) and then run dpkg
# --add-architecture arm64 to be able to retrieve and install it.
#
# Furthermore, we need to mark the repos in /etc/apt/sources.list (usually
# archive.ubuntu.org) as explicitly being amd64 only. Otherwise apt will look
# for aarch64 packages there after we run dpkg --add-architecture arm64. This
# will cause failures as Ubuntu doesn't store aarch64 packages at
# archive.ubuntu.org.
RUN echo "deb [arch=arm64] http://ports.ubuntu.com/ jammy main restricted" >> /etc/apt/sources.list.d/arm-sources.list \
    && echo "deb [arch=arm64] http://ports.ubuntu.com/ jammy-updates main restricted" >> /etc/apt/sources.list.d/arm-sources.list \
    && echo "deb [arch=arm64] http://ports.ubuntu.com/ jammy universe" >> /etc/apt/sources.list.d/arm-sources.list \
    && echo "deb [arch=arm64] http://ports.ubuntu.com/ jammy-updates universe" >> /etc/apt/sources.list.d/arm-sources.list \
    && echo "deb [arch=arm64] http://ports.ubuntu.com/ jammy multiverse" >> /etc/apt/sources.list.d/arm-sources.list \
    && echo "deb [arch=arm64] http://ports.ubuntu.com/ jammy-updates multiverse" >> /etc/apt/sources.list.d/arm-sources.list \
    && echo "deb [arch=arm64] http://ports.ubuntu.com/ jammy-backports main restricted universe multiverse" >> /etc/apt/sources.list.d/arm-sources.list \
    && dpkg --add-architecture arm64 \
    && sed -i 's/deb/deb [arch=amd64]/g' /etc/apt/sources.list \
    && apt-get update

RUN apt-get update -y && \
    apt-get install -y --no-install-recommends \
        llvm \
        clang \
        clang-format \
        gcc-aarch64-linux-gnu \
        g++-aarch64-linux-gnu \
        libz-dev:arm64 \
        libz-dev \
        m4 \
        cmake \
        make \
        build-essential \
        groff-base \
        bmake \
        linux-tools-generic linux-tools-${LINUX_TOOLS_VERSION}-generic && \
    apt-get autoremove -y --purge && apt-get autoclean && apt-get clean && \
    sed -i -e 's/-soname /-soname=/g' /usr/share/mk/lib.mk && \
    update-alternatives --install /usr/local/sbin/bpftool bpftool /usr/lib/linux-tools-${LINUX_TOOLS_VERSION}/bpftool 1
