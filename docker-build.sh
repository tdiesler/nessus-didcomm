#!/bin/bash

# exit when any command fails
set -e

WORKDIR=$(realpath $(dirname $0))
TARGET_DIR="${WORKDIR}/docker/target"

echo "WORKDIR=${WORKDIR}"
cd ${WORKDIR}

if [[ -z ${NESSUS_DIDCOMM_VERSION} ]]; then
    NESSUS_DIDCOMM_VERSION="dev"
fi

function buildImage () {

    imageName="nessusio/nessus-didcomm"
    fullName="${imageName}:${NESSUS_DIDCOMM_VERSION}"

    rm -rf ${TARGET_DIR}
    mkdir -p "${TARGET_DIR}/distro"

    cp -r ./cli/target/distro ${TARGET_DIR}

    echo "Building ${fullName} ..."
    docker build -t ${fullName} -f ./docker/Dockerfile ${TARGET_DIR}
    docker tag ${fullName} "${imageName}:latest"
}

buildImage
