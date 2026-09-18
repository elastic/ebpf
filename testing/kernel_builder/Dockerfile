from debian:bullseye@sha256:6f519a81440354a85eb592c5f32109ab80605f6b892455983a6f618bf87fabe9

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
