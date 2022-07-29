ARCH ?= $(shell arch)

DOCKER_IMAGE = us-docker.pkg.dev/elastic-security-dev/ebpf-public/builder
DOCKER_PULL_TAG = 20220711-1742
DOCKER_LOCAL_TAG = ${USER}-latest
CURRENT_DATE_TAG = $(shell date +%Y%m%d-%H%M)

PWD = $(shell pwd)
BUILD_DIR = artifacts-${ARCH}
CMAKE_FLAGS = -DARCH=${ARCH} -DBUILD_STATIC_EVENTSTRACE=True -DUSE_BUILTIN_VMLINUX=True -B${BUILD_DIR} -S${PWD}

# Directories to search recursively for c/cpp source files to clang-format
FORMAT_DIRS = GPL/ non-GPL/ testing/test_bins

.PHONY = build build-debug _internal-build clean container format test-format

# Kludge to get around a missing header. If we don't do this, we'll get the following error when
# building:
#
# In file included from /home/vagrant/ebpf/contrib/libbpf/include/uapi/linux/bpf.h:11:
# In file included from /home/vagrant/ebpf/contrib/libbpf/include/linux/types.h:8:
# In file included from /usr/lib/llvm-14/lib/clang/14.0.0/include/stdint.h:52:
# /usr/include/stdint.h:26:10: fatal error: 'bits/libc-header-start.h' file not found
# include <bits/libc-header-start.h>
#        ^~~~~~~~~~~~~~~~~~~~~~~~~~
#
# The HostIsolation probes include linux/bpf.h (copied into the libbpf repo) which includes
# linux/types.h (also copied into the libbpf repo) which includes stdint.h. The clang stdint.h
# includes bits/libc-header-start.h which is not in our include path. The correct one to use
# depends on which arch we're compiling for.
ifeq ($(ARCH),x86_64)
	export C_INCLUDE_PATH = /usr/include/x86_64-linux-gnu
else
	export C_INCLUDE_PATH = /usr/aarch64-linux-gnu/include
endif

export CC=${ARCH}-linux-gnu-gcc
export CXX=${ARCH}-linux-gnu-g++
export AR=${ARCH}-linux-gnu-ar
export LD=${ARCH}-linux-gnu-ld

build:
	docker run --rm -v${PWD}:${PWD} -w${PWD} ${DOCKER_IMAGE}:${DOCKER_PULL_TAG} \
		/usr/bin/env make _internal-build ARCH=${ARCH} EXTRA_CMAKE_FLAGS=${EXTRA_CMAKE_FLAGS}
	sudo chown -fR ${USER}:${USER} ${BUILD_DIR}
	@echo "\n++ Build Successful at `date` ++\n"

# Convenience target to pass -DCMAKE_BUILD_TYPE=Debug and -DCMAKE_C_FLAGS="-g -O0"
build-debug:
	docker run --rm -v${PWD}:${PWD} -w${PWD} ${DOCKER_IMAGE}:${DOCKER_PULL_TAG} \
		/usr/bin/env make _internal-build ARCH=${ARCH} EXTRA_CMAKE_FLAGS='-DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-g -O0"'
	sudo chown -fR ${USER}:${USER} ${BUILD_DIR}
	@echo "\n++ Build Successful at `date` ++\n"

_internal-build:
	mkdir -p ${BUILD_DIR}/
	cmake ${EXTRA_CMAKE_FLAGS} ${CMAKE_FLAGS}
	make VERBOSE=1 -C${BUILD_DIR} -j$(shell nproc)

container:
	docker build -t ${DOCKER_LOCAL_TAG} -f docker/Dockerfile.builder .

tag-container:
	docker tag ${DOCKER_IMAGE}:${DOCKER_LOCAL_TAG} ${DOCKER_IMAGE}:$CURRENT_DATE_TAG
	@echo "\n++ Tagged image as ${DOCKER_IMAGE}:${CURRENT_DATE_TAG} ++\n"

# We dockerize code formatting because differences in clang-format versions can
# lead to different formatting decisions. This way, everyone is using
# clang-format 14 (default in the Ubuntu jammy repos).
format:
	docker run --rm -v${PWD}:${PWD} -w${PWD} ${DOCKER_IMAGE}:${DOCKER_PULL_TAG} \
		sh -c 'find ${FORMAT_DIRS} -name "*.cpp" -o -name "*.c" -o -name "*.h" -o -name "*.cpp" | xargs /usr/bin/env clang-format -i'

test-format:
	docker run --rm -v${PWD}:${PWD} -w${PWD} ${DOCKER_IMAGE}:${DOCKER_PULL_TAG} \
		sh -c 'find ${FORMAT_DIRS} -name "*.cpp" -o -name "*.c" -o -name "*.h" -o -name "*.cpp" | xargs /usr/bin/env clang-format -i --dry-run -Werror'

clean:
	sudo rm -rf artifacts-*
