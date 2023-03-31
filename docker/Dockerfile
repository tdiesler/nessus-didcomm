FROM azul/zulu-openjdk-alpine:18.0.2.1-jre

RUN apk add libsodium

COPY target/distro /nessus-didcomm

ENV NESSUS_HOME="/nessus-didcomm"
WORKDIR "/nessus-didcomm"

ENTRYPOINT ["./bin/didcomm.sh"]
