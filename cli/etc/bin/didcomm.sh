#!/bin/sh

NESSUS_DIDCOMM_HOME=$(realpath $0/../..)
cd $NESSUS_DIDCOMM_HOME

java -Dlogback.configurationFile=config/logback.xml -DserviceMatrixProperties=config/service-matrix.properties \
  -jar nessus-didcomm-cli-@project.version@.jar "$@"