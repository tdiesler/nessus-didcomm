#!/bin/sh

if [[ -z ${NESSUS_HOME} ]]; then
  NESSUS_HOME=$(realpath $0/../..)
fi

# Change the working dir
cd ${NESSUS_HOME}

if [[ $1 == "run" ]] && [[ $2 == "--headless" ]]; then
  LOGBACK_CONFIG="config/logback-headless.xml"
  if [[ -z ${NESSUS_USER_PORT} ]]; then
    export NESSUS_USER_PORT="9100"
  fi
elif [[ -z ${LOGBACK_CONFIG} ]]; then
  LOGBACK_CONFIG="config/logback.xml"
fi

if [[ -z ${SERVICE_MATRIX_CONFIG} ]]; then
  SERVICE_MATRIX_CONFIG="config/service-matrix.properties"
fi

# echo "NESSUS_HOME=${NESSUS_HOME}"
# echo "SERVICE_MATRIX_CONFIG=${SERVICE_MATRIX_CONFIG}"
# echo "LOGBACK_CONFIG=${LOGBACK_CONFIG}"

java -Dlogback.configurationFile=${LOGBACK_CONFIG} -DserviceMatrixProperties=${SERVICE_MATRIX_CONFIG} \
  -jar nessus-didcomm-cli-@project.version@.jar "$@"