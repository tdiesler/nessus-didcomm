#!/bin/bash

SCRIPT_DIR=$(realpath $(dirname $0))
source $SCRIPT_DIR/build-common.sh

echo "Building ${fullName} ..."
docker build -t ${fullName} ${SCRIPT_DIR}
docker tag ${fullName} "${imageName}:${LATEST_VERSION}"
