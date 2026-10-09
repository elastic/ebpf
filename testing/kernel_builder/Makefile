CONTAINER_ENGINE ?= docker

IMAGE=kernel-builder-local
TAG=latest

all:
	${CONTAINER_ENGINE} run -e BUILD_ARCHES -e BUILD_VERSIONS -e KEEP_VMLINUX -v ${PWD}:/work ${IMAGE}-new:${TAG}

image:
	${CONTAINER_ENGINE} build -f Dockerfile -t ${IMAGE}-new:${TAG} .
