ARG PULL_TAG=jammy

FROM ubuntu:${PULL_TAG}

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
    && apt-get autoremove -y --purge && apt-get clean \
    && sed -i -e 's/-soname /-soname=/g' /usr/share/mk/lib.mk

CMD [ \
    "/usr/bin/env", \
    "C_INCLUDE_PATH=/usr/include/`arch`-linux-gnu", \
    "make", \
    "build-local" \
]
