ARCH ?= $(shell arch)
BUILD_DIR ?= artifacts-${ARCH}
PWD = $(shell pwd)
DOCKER_IMG_UBUNTU_VERSION ?= jammy
BUILDER_PULL_TAG ?= us-docker.pkg.dev/elastic-security-dev/ebpf-public/builder:20220621-0034
BUILDER_TAG ?= us-docker.pkg.dev/elastic-security-dev/ebpf-public/builder:${USER}-latest
CMAKE_FLAGS = -DARCH=${ARCH} -DBUILD_STATIC_EVENTSTRACE=True -DUSE_BUILTIN_VMLINUX=True -B${BUILD_DIR} -S${PWD}

.PHONY = build build-debug build-local clean container fix-permissions format test-format

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
	docker run --rm -v${PWD}:${PWD} -w${PWD} ${BUILDER_PULL_TAG} \
		/usr/bin/env make _internal-build ARCH=${ARCH} EXTRA_CMAKE_FLAGS=${EXTRA_CMAKE_FLAGS}
	sudo chown -fR ${USER}:${USER} ${BUILD_DIR}
	@echo "\n++ Build Successful at `date` ++\n"

# Convenience target to pass -DCMAKE_BUILD_TYPE=Debug and -DCMAKE_C_FLAGS="-g -O0"
build-debug:
	docker run --rm -v${PWD}:${PWD} -w${PWD} ${BUILDER_PULL_TAG} \
		/usr/bin/env make _internal-build-debug ARCH=${ARCH} EXTRA_CMAKE_FLAGS=${EXTRA_CMAKE_FLAGS}
	sudo chown -fR ${USER}:${USER} ${BUILD_DIR}
	@echo "\n++ Build Successful at `date` ++\n"

_internal-build-debug: CMAKE_FLAGS = -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-g -O0" ${CMAKE_COMMON_FLAGS}
_internal-build-debug: _internal-build
_internal-build:
	mkdir -p ${BUILD_DIR}/
	cmake ${EXTRA_CMAKE_FLAGS} ${CMAKE_FLAGS}
	make -C${BUILD_DIR} -j$(shell nproc)

container:
	docker build -t ${BUILDER_TAG} -f docker/Dockerfile.builder .

format:
	find non-GPL/ GPL/ testing/test_bins/ -name "*.c" -o -name "*.h" -o -name "*.cpp" | \
		xargs /usr/bin/env clang-format -i

test-format:
	find non-GPL/ GPL/ testing/test_bins/ -name "*.c" -o -name "*.h" -o -name "*.cpp" | \
		xargs /usr/bin/env clang-format -i --dry-run -Werror

clean:
	sudo rm -rf artifacts-*
