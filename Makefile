ARCH ?= $(shell arch)
SUDO ?= $(shell which sudo 2>/dev/null)
USER ?= $(shell whoami)
CURRENT_DATE_TAG ?= $(shell date +%Y%m%d-%H%M)

# bmake Settings
MAKE_SYS_PATH ?= /usr/share/mk
export MAKESYSPATH = ${MAKE_SYS_PATH}

# Container Settings
NOCONTAINER ?=
BUILD_CONTAINER_IMAGE ?=

CONTAINER_ENGINE ?= docker
CONTAINER_REPOSITORY ?= ghcr.io/elastic/ebpf-builder
CONTAINER_PULL_TAG ?= 20220731-1104
CONTAINER_LOCAL_TAG ?= ebpf-builder:${USER}-latest

IMAGEPACK_REPOSITORY ?= ghcr.io/elastic/ebpf-imagepack
IMAGEPACK_PULL_TAG ?= 20220812-1344

ifdef BUILD_CONTAINER_IMAGE
	CONTAINER_IMAGE = ${CONTAINER_LOCAL_TAG}
else
	CONTAINER_IMAGE ?= ${CONTAINER_REPOSITORY}:${CONTAINER_PULL_TAG}
	CONTAINER_RELEASE_IMAGE ?= ${CONTAINER_REPOSITORY}:${CURRENT_DATE_TAG}
endif

ifdef NOCONTAINER
	CONTAINER_RUN_CMD = 
else
	CONTAINER_RUN_CMD = ${CONTAINER_ENGINE} run --platform linux/${ARCH} --rm -v${PWD}:${PWD} -w${PWD} -e NOCONTAINER=TRUE ${CONTAINER_IMAGE}
endif

PWD = $(shell pwd)
BUILD_DIR = artifacts-${ARCH}
CMAKE_FLAGS = -DARCH=${ARCH} -DBUILD_STATIC_EVENTSTRACE=True

# Debug settings
ifdef DEBUG
	CMAKE_FLAGS = ${CMAKE_FLAGS} -DCMAKE_BUILD_TYPE=Debug -DCMAKE_C_FLAGS="-g -O0"
endif
# Directories to search recursively for c/cpp source files to clang-format
FORMAT_DIRS = GPL/ non-GPL/ testing/test_bins

.PHONY = build clean container format test-format release-container fix-permissions update-kims kip

build:
ifdef NOCONTAINER
	mkdir -p ${BUILD_DIR}/
	cmake ${EXTRA_CMAKE_FLAGS} ${CMAKE_FLAGS} -B${BUILD_DIR} -S${PWD}
	cmake --build ${BUILD_DIR} --parallel $(shell nproc)
	@echo -e "\n++ Build Successful at `date` ++\n"
else
ifdef BUILD_CONTAINER_IMAGE
	make container
endif
	${CONTAINER_RUN_CMD} \
	make build DEBUG=${DEBUG} ARCH=${ARCH} EXTRA_CMAKE_FLAGS=${EXTRA_CMAKE_FLAGS}
	make fix-permissions
endif

container:
	${CONTAINER_ENGINE} buildx build --progress plain --platform=linux/${ARCH} -t ${CONTAINER_LOCAL_TAG} -f docker/Dockerfile.builder .

tag-container:
	${CONTAINER_ENGINE} tag ${CONTAINER_LOCAL_TAG} ${CONTAINER_IMAGE}
	@echo -e "\n++ Tagged image as ${CONTAINER_IMAGE} ++\n"

release-container:
	${CONTAINER_ENGINE} buildx build --progress plain --platform linux/amd64 \
	-t ${CONTAINER_RELEASE_IMAGE}-amd64 -f docker/Dockerfile.builder .
	
	${CONTAINER_ENGINE} buildx build --progress plain --platform linux/arm64 \
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
	make container
endif
	${CONTAINER_RUN_CMD} make format
	make fix-permissions
endif

test-format:
ifdef NOCONTAINER
	sh -c 'find ${FORMAT_DIRS} -name "*.cpp" -o -name "*.c" -o -name "*.h" -o -name "*.cpp" | xargs clang-format -i --dry-run -Werror'
else
ifdef BUILD_CONTAINER_IMAGE
	make container
endif
	${CONTAINER_RUN_CMD} make test-format
endif

# Update kernel images from gcs
update-kims:
	@mkdir -p LargeFiles
	gsutil -m rsync -r gs://ebpf-ci-kernel-images LargeFiles

# Build Containerized Kernel Image Pack
build-kip:
	${CONTAINER_ENGINE} build --no-cache -t ${IMAGEPACK_REPOSITORY}:${CURRENT_DATE_TAG} -f docker/Dockerfile.imagepack ./LargeFiles

get-kernel-images:
	mkdir -p ./kernel-images/
ifdef IMG_FILTER
	${CONTAINER_ENGINE} run --rm -v${PWD}/kernel-images:/kernel-images ${IMAGEPACK_REPOSITORY}:${IMAGEPACK_PULL_TAG} cp -r /kernel-img-repository/${IMG_FILTER} ./kernel-images/
else
	${CONTAINER_ENGINE} run --rm -v${PWD}/kernel-images:/kernel-images ${IMAGEPACK_REPOSITORY}:${IMAGEPACK_PULL_TAG}
endif
	${SUDO} chown -fR ${USER}:${USER} .

multi-kernel-test:
ifndef IMG_FILTER
	@echo Must set IMG_FILTER
	exit 1
endif
	go install github.com/florianl/bluebox@b8590fb1850f56df6e6d7786931fcabdc1e9173d
	cd testing && ./run_tests.sh ${ARCH} ${PWD}/artifacts-${ARCH}/non-GPL/Events/EventsTrace/EventsTrace ${PWD}/kernel-images/${IMG_FILTER}/${ARCH}/*

fix-permissions:
	${SUDO} chown -fR ${USER}:${USER} .

clean:
	${SUDO} rm -rf artifacts-*
