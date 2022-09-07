CONTAINER_ENGINE ?= docker

IMAGE=kernel-builder-local
TAG=latest

all:
	${CONTAINER_ENGINE} run -v ${PWD}:/work ${IMAGE}:${TAG}

image:
	${CONTAINER_ENGINE} build . -t ${IMAGE}:${TAG}
