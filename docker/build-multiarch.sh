#!/bin/bash

SCRIPT_DIR=$(realpath $(dirname $0))
source $SCRIPT_DIR/build-common.sh

# Do this once
# docker buildx create --name mybuilder --use

echo "Building ${imageName}:${FULL_VERSION} ..."
docker buildx build --platform linux/amd64,linux/arm64 --push -t ${imageName}:${FULL_VERSION} ${SCRIPT_DIR}
docker buildx build --platform linux/amd64,linux/arm64 --push -t ${imageName}:${LATEST_VERSION} ${SCRIPT_DIR}

docker pull ${imageName}:${LATEST_VERSION}