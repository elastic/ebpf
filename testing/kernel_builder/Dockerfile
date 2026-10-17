from debian:bookworm@sha256:2c037a04925515fdd6ea85ea14a682d0e79931f5e9f5d07b6dbfc6ba12f9e858

RUN dpkg --add-architecture arm64
RUN apt-get -y update
RUN apt-get -y install \
        git gcc make libssl-dev bison flex bc libelf-dev python3 \
        gcc-aarch64-linux-gnu curl dwarves xz-utils \
        cmake zlib1g libdw1 libdw-dev rsync

RUN git clone https://git.kernel.org/pub/scm/devel/pahole/pahole.git /pahole
WORKDIR /pahole
RUN git submodule update --init --recursive
RUN mkdir /pahole/build
WORKDIR /pahole/build
RUN cmake -DBUILD_SHARED_LIBS=OFF ..
RUN make install

WORKDIR /work
CMD ./build.sh
