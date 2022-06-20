ARCH ?= $(shell arch)
BUILD_DIR ?= artifacts-${ARCH}
SKELETON_BUILD_DIR ?= ${BUILD_DIR}-skel
SUDO ?= 
PWD ?= $(shell pwd)
CONTAINER_RUNTIME ?= docker
DOCKER_IMG_UBUNTU_VERSION ?= jammy
BUILDER_PULL_TAG ?= us-docker.pkg.dev/elastic-security-dev/ebpf-public/builder:20220620-0715
BUILDER_TAG ?= us-docker.pkg.dev/elastic-security-dev/ebpf-public/builder:${USER}-latest
C_INCLUDE_PATH ?=
DOCKER_CACHE ?=


.PHONY = gen-skeleton build build-local clean container fix-permissions format test-format

container:
	${CONTAINER_RUNTIME} build ${DOCKER_CACHE} -t ${BUILDER_TAG} --build-arg PULL_TAG=${DOCKER_IMG_UBUNTU_VERSION} -f docker/Dockerfile.builder .

gen-skeleton:
	docker run --rm -v${PWD}:${PWD} -w${PWD} ${BUILDER_PULL_TAG} make gen-skeleton-local

gen-skeleton-local:
	mkdir -p ${SKELETON_BUILD_DIR}
	cmake -DUSE_BUILTIN_VMLINUX=True -B${SKELETON_BUILD_DIR} -S${PWD}
	make -C${SKELETON_BUILD_DIR}/GPL/EventProbe
	bpftool gen skeleton ${PWD}/${SKELETON_BUILD_DIR}/target/ebpf/EventProbe.bpf.o > /dev/null && bpftool gen skeleton ${PWD}/${SKELETON_BUILD_DIR}/target/ebpf/EventProbe.bpf.o > ${PWD}/non-GPL/include/EventProbe.skel.h

build-local:
	mkdir -p ${BUILD_DIR}
	C_INCLUDE_PATH=${C_INCLUDE_PATH} cmake -DUSE_BUILTIN_VMLINUX=True -B${BUILD_DIR} -S${PWD}
	C_INCLUDE_PATH=${C_INCLUDE_PATH} make -C${BUILD_DIR}

build:
	docker run --rm -v${PWD}:${PWD} -w${PWD} ${BUILDER_PULL_TAG} 
	@echo "\n++ Build Successful at `date` ++\n"

fix-permissions:
	sudo chown -fR ${USER}:${USER} ${BUILD_DIR}

format:
	find . \( -path ./contrib -o -path ./artifacts* -o -path ./non-GPL/include/EventProbe.skel.h \) -prune \
	-o -name "*.c" -o -name "*.cpp" -o -name "*.h" -print | xargs /usr/bin/env clang-format -i

test-format:
	find . \( -path ./contrib -o -path ./artifacts* -o -path ./non-GPL/include/EventProbe.skel.h \) -prune \
	-o -name "*.c" -o -name "*.cpp" -o -name "*.h" -print | xargs /usr/bin/env clang-format --dry-run -Werror

clean:
	${SUDO} rm -rf artifacts-*
