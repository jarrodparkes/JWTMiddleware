# variables
DOCKERFILE=Dockerfile
IMAGE=kitura-jwt
CONTAINER_NAME=kitura-jwt
CONTAINER_PORT=8080
HOST_PORT=80

image_build:
	docker build -t ${IMAGE} -f ${DOCKERFILE} .

dev:
	docker run --name ${CONTAINER_NAME} \
	-it --rm -v ${PWD}:/src \
	-w /src \
	-p ${HOST_PORT}:${CONTAINER_PORT} ${IMAGE} /bin/bash

build:
	swift build -Xlinker -L/usr/local/lib

clean:
	rm -rf .build
	rm Package.pins

unit_test:
	swift test
