#!/bin/bash

NESSUS_DIDCOMM_VER="23.4.0"
NESSUS_DIDCOMM_REV="-dev"

# exit when any command fails
set -e

SCRIPT_DIR=$(realpath $(dirname $0))
TARGET_DIR="${SCRIPT_DIR}/target"

rm -rf ${TARGET_DIR}
mkdir -p ${TARGET_DIR}
cp -r ${SCRIPT_DIR}/../cli/target/distro ${TARGET_DIR}/

VERSION_MAJOR=${NESSUS_DIDCOMM_VER}
VERSION_REV=${NESSUS_DIDCOMM_REV}

if [[ "${VERSION_REV}" == "" ]]; then
  FULL_VERSION="${VERSION_MAJOR}"
  LATEST_VERSION="latest"

elif [[ "${VERSION_REV}" == "-dev" ]]; then
  FULL_VERSION="${VERSION_MAJOR}-dev"
  LATEST_VERSION="dev"

else
  FULL_VERSION="${VERSION_MAJOR}${VERSION_REV}"
  LATEST_VERSION="latest"
fi

imageName="nessusio/nessus-didcomm"
fullName="${imageName}:${FULL_VERSION}"


# Do this once
# docker buildx create --name mybuilder --use

echo "Building ${fullName} ..."
docker buildx build --platform linux/amd64,linux/arm64 --push -t ${imageName}:${FULL_VERSION} ${SCRIPT_DIR}
docker buildx build --platform linux/amd64,linux/arm64 --push -t ${imageName}:${LATEST_VERSION} ${SCRIPT_DIR}

docker pull ${imageName}:${LATEST_VERSION}