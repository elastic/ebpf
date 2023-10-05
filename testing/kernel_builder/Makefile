CONTAINER_ENGINE ?= docker

IMAGE=kernel-builder-local
TAG=latest

all:
	${CONTAINER_ENGINE} run -v ${PWD}:/work ${IMAGE}-old:${TAG}
	${CONTAINER_ENGINE} run -v ${PWD}:/work ${IMAGE}-new:${TAG}

image:
	${CONTAINER_ENGINE} build -f Dockerfile.old -t ${IMAGE}-old:${TAG}
	${CONTAINER_ENGINE} build -f Dockerfile.new -t ${IMAGE}-new:${TAG}
