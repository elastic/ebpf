FROM ubuntu:focal

RUN apt-get update && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y \
    gcc-9 \
    g++-9 \
    make \
    bmake \
    m4 \
    build-essential \
    autoconf \
    automake \
    wget \
    linux-tools-`uname -r` linux-headers-`uname -r` \
    llvm-11 \
    clang-11 \
    libz-dev \
    curl \
    && apt-get autoremove --purge

#Install newer cmake than what apt provides
RUN wget -qO- "https://cmake.org/files/v3.22/cmake-3.22.1-linux-`arch`.tar.gz" | tar --strip-components=1 -xz -C /usr/local

RUN update-alternatives --install /usr/bin/clang++ clang++ /usr/bin/clang++-11 1 \
    && update-alternatives --install /usr/bin/clang clang /usr/bin/clang-11 1 \
    && update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-9 1 \
    && update-alternatives --install /usr/bin/llc llc /usr/bin/llc-11 1 \
    && update-alternatives --install /usr/bin/llvm-strip llvm-strip /usr/bin/llvm-strip-11 1

# Install google cloud sdk
RUN echo "deb [signed-by=/usr/share/keyrings/cloud.google.gpg] http://packages.cloud.google.com/apt cloud-sdk main" | tee -a /etc/apt/sources.list.d/google-cloud-sdk.list && curl https://packages.cloud.google.com/apt/doc/apt-key.gpg | apt-key --keyring /usr/share/keyrings/cloud.google.gpg add - && apt-get update -y && apt-get install google-cloud-sdk -y

RUN apt-get autoremove -y --purge && apt-get -y clean && apt-get -y autoclean

# RUN echo "export C_INCLUDE_PATH=/usr/include/`arch`-linux-gnu" > /etc/profile.d/02-ebpf-builder.sh

# CMD /bin/bash -c "source /etc/profile && rm -rf /ebpf/build && mkdir -p /ebpf/build && cd /ebpf/build && cmake ../ && make"


# sudo docker build --platform linux/amd64 --tag ebpf-builder - < Dockerfile
# sudo docker run -it --rm --name ebpf-builder --mount type=bind,source="$(pwd)",target=/ebpf ebpf-builder:latest
# cmake -DBUILD_STATIC_EVENTSTRACE=TRUE ../
#C_INCLUDE_PATH=/usr/include/`arch`-linux-gnu make
