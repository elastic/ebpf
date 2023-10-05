ARCH ?= $(shell arch)
SUDO ?= $(shell which sudo 2>/dev/null)
USER ?= $(shell whoami)
CURRENT_DATE_TAG ?= $(shell date +%Y%m%d-%H%M)
PKG_VERSION ?= $(shell cat VERSION)

# bmake Settings
MAKE_SYS_PATH ?= /usr/share/mk
export MAKESYSPATH = ${MAKE_SYS_PATH}

# Container Settings
NOCONTAINER ?=
BUILD_CONTAINER_IMAGE ?=
NO_CACHE ?=

CONTAINER_ENGINE ?= docker
CONTAINER_REPOSITORY ?= ghcr.io/elastic/ebpf-builder
CONTAINER_PULL_TAG ?= 20221121-1315
CONTAINER_LOCAL_TAG ?= ebpf-builder:${USER}-latest

IMAGEPACK_REPOSITORY ?= ghcr.io/elastic/ebpf-imagepack
IMAGEPACK_PULL_TAG ?= 20231006-0053

ifdef BUILD_CONTAINER_IMAGE
	CONTAINER_IMAGE = ${CONTAINER_LOCAL_TAG}
else
	CONTAINER_IMAGE ?= ${CONTAINER_REPOSITORY}:${CONTAINER_PULL_TAG}
	CONTAINER_RELEASE_IMAGE ?= ${CONTAINER_REPOSITORY}:${CURRENT_DATE_TAG}
endif

ifdef NOCONTAINER
	CONTAINER_RUN_CMD =
else
ifeq ($(CONTAINER_ENGINE),podman)
	EXTRA_FLAGS = --userns=keep-id
else
	EXTRA_FLAGS =
endif
	CONTAINER_RUN_CMD = ${CONTAINER_ENGINE} run --platform linux/${ARCH} --rm -v${PWD}:${PWD} -w${PWD} -u$(shell id -u):$(shell id -g) ${EXTRA_FLAGS} -e NOCONTAINER=TRUE ${CONTAINER_IMAGE}
endif

PWD = $(shell pwd)
BUILD_DIR ?= ${PWD}/artifacts-${ARCH}
PKG_DIR ?= ${BUILD_DIR}/package
MDATA_DIR ?= ${BUILD_DIR}/package/share/elastic/ebpf
CMAKE_FLAGS = -DARCH=${ARCH}
ARTIFACTS_PATH ?= ${PWD}/artifacts-${ARCH}

# Debug settings
ifdef DEBUG
	CMAKE_FLAGS += -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-g -O0"
endif

# Directories to search recursively for c/cpp source files to clang-format
FORMAT_DIRS = GPL/ non-GPL/ testing/test_bins

.PHONY = build package clean container format test-format release-container update-kims kip

build:
ifdef NOCONTAINER
	mkdir -p ${BUILD_DIR}/
	cmake ${EXTRA_CMAKE_FLAGS} ${CMAKE_FLAGS} -B${BUILD_DIR} -S${PWD}
	cmake --build ${BUILD_DIR} --parallel $(shell nproc)
	@echo -e "\n++ Build Successful at `date` ++\n"
else
ifdef BUILD_CONTAINER_IMAGE
	${MAKE} container
endif
	${CONTAINER_RUN_CMD} \
	${MAKE} build DEBUG=${DEBUG} ARCH=${ARCH} EXTRA_CMAKE_FLAGS=${EXTRA_CMAKE_FLAGS}
endif

package:
ifdef NOCONTAINER
	@echo "Packaging ebpf version: ${PKG_VERSION}"
	cmake --install ${BUILD_DIR} --prefix ${PKG_DIR}
	mkdir -p ${MDATA_DIR}
	cp VERSION ${MDATA_DIR}
	cp NOTICE.txt ${MDATA_DIR}
	cp LICENSE.txt ${MDATA_DIR}
	cd ${PKG_DIR} && tar -czf ${BUILD_DIR}/elastic-ebpf-${PKG_VERSION}-SNAPSHOT.tar.gz *
	@echo -e "\n++ Packaging Successful at `date` ++\n"
else
ifdef BUILD_CONTAINER_IMAGE
	${MAKE} container
endif
	${CONTAINER_RUN_CMD} \
	${MAKE} package DEBUG=${DEBUG} ARCH=${ARCH} EXTRA_CMAKE_FLAGS=${EXTRA_CMAKE_FLAGS}
endif

container:
	${CONTAINER_ENGINE} buildx build ${NO_CACHE} --progress plain --platform=linux/${ARCH} -t ${CONTAINER_LOCAL_TAG} -f docker/Dockerfile.builder .

tag-container:
	${CONTAINER_ENGINE} tag ${CONTAINER_LOCAL_TAG} ${CONTAINER_IMAGE}
	@echo -e "\n++ Tagged image as ${CONTAINER_IMAGE} ++\n"

release-container:
	${CONTAINER_ENGINE} buildx build ${NO_CACHE} --progress plain --platform linux/amd64 \
	-t ${CONTAINER_RELEASE_IMAGE}-amd64 -f docker/Dockerfile.builder .

	${CONTAINER_ENGINE} buildx build ${NO_CACHE} --progress plain --platform linux/arm64 \
	-t ${CONTAINER_RELEASE_IMAGE}-arm64 -f docker/Dockerfile.builder .

	${CONTAINER_ENGINE} push ${CONTAINER_RELEASE_IMAGE}-arm64
	${CONTAINER_ENGINE} push ${CONTAINER_RELEASE_IMAGE}-amd64

	${CONTAINER_ENGINE} manifest create ${CONTAINER_RELEASE_IMAGE} \
	--amend ${CONTAINER_RELEASE_IMAGE}-arm64 \
	--amend ${CONTAINER_RELEASE_IMAGE}-amd64

	${CONTAINER_ENGINE} manifest annotate ${CONTAINER_RELEASE_IMAGE} ${CONTAINER_RELEASE_IMAGE}-arm64 --arch arm64
	${CONTAINER_ENGINE} manifest annotate ${CONTAINER_RELEASE_IMAGE} ${CONTAINER_RELEASE_IMAGE}-amd64 --arch amd64
	${CONTAINER_ENGINE} manifest push ${CONTAINER_RELEASE_IMAGE}
	${CONTAINER_ENGINE} manifest rm ${CONTAINER_RELEASE_IMAGE}

	@echo -e "\n++ Successfully released image: ${CONTAINER_RELEASE_IMAGE} ++\n"

format:
ifdef NOCONTAINER
	sh -c 'find ${FORMAT_DIRS} -name "*.cpp" -o -name "*.c" -o -name "*.h" -o -name "*.cpp" | xargs clang-format -i'
else
ifdef BUILD_CONTAINER_IMAGE
	${MAKE} container
endif
	${CONTAINER_RUN_CMD} ${MAKE} format
endif

test-format:
ifdef NOCONTAINER
	sh -c 'find ${FORMAT_DIRS} -name "*.cpp" -o -name "*.c" -o -name "*.h" -o -name "*.cpp" | xargs clang-format -i --dry-run -Werror'
else
ifdef BUILD_CONTAINER_IMAGE
	@${MAKE} container
endif
	${CONTAINER_RUN_CMD} ${MAKE} test-format
endif

# Update kernel images from gcs
update-kims:
	@mkdir -p LargeFiles
	gsutil -m rsync -d -r gs://ebpf-ci-kernel-images LargeFiles

# Build Containerized Kernel Image Pack(s)
build-kips:
	for dir in $(shell ls ./LargeFiles); do \
	${CONTAINER_ENGINE} build -t ${IMAGEPACK_REPOSITORY}:$${dir}-${CURRENT_DATE_TAG} -f docker/Dockerfile.imagepack --build-arg IMGPACK_FILTER=$${dir} ./LargeFiles/$${dir}; \
	done

publish-kips:
	@${MAKE} build-kips CURRENT_DATE_TAG=${CURRENT_DATE_TAG}
	@for dir in $(shell ls ./LargeFiles); do \
    ${CONTAINER_ENGINE} push ${IMAGEPACK_REPOSITORY}:$${dir}-${CURRENT_DATE_TAG}; \
	done

get-kernel-images:
	mkdir -p ./kernel-images/
ifndef IMG_FILTER
	@echo Must set IMG_FILTER
	exit 1
endif
	${CONTAINER_ENGINE} run --rm -v${PWD}/kernel-images:/kernel-images ${IMAGEPACK_REPOSITORY}:${IMG_FILTER}-${IMAGEPACK_PULL_TAG} cp -r /kernel-img-repository/${IMG_FILTER} ./kernel-images/
	${SUDO} chown -fR ${USER}:${USER} .

run-multikernel-test: get-kernel-images
ifndef IMG_FILTER
	@echo Must set IMG_FILTER
	exit 1
endif
	go install github.com/florianl/bluebox@b8590fb1850f56df6e6d7786931fcabdc1e9173d
	cd testing && ./run_tests.sh ${ARCH} ${ARTIFACTS_PATH} ${PWD}/kernel-images/${IMG_FILTER}/${ARCH}/*

clean:
	${SUDO} rm -rf artifacts-*
