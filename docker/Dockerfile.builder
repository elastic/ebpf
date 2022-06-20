ARG PULL_TAG=jammy

FROM ubuntu:${PULL_TAG}

ARG BPFTOOL_VERSION=5.15.0-33
ENV BPFTOOL_VERSION=${BPFTOOL_VERSION}

RUN DEBIAN_FRONTEND=noninteractive apt-get update -y \
    && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        llvm \
        clang \
        libz-dev \
        m4 \
        cmake \
        make \
        build-essential \
        groff-base \
        bmake \
        linux-tools-generic linux-tools-${BPFTOOL_VERSION}-generic \
    && apt-get autoremove -y --purge && apt-get autoclean && apt-get clean \
    && sed -i -e 's/-soname /-soname=/g' /usr/share/mk/lib.mk \
    && update-alternatives --install /usr/local/sbin/bpftool bpftool /usr/lib/linux-tools-${BPFTOOL_VERSION}/bpftool 1

CMD [ \
    "/usr/bin/env", \
    "C_INCLUDE_PATH=/usr/include/`arch`-linux-gnu", \
    "make", \
    "build-local" \
]
