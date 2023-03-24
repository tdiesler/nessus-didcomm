FROM azul/zulu-openjdk-alpine:18.0.2-jre

RUN apk add libsodium

# Copy to nessus-pulsex
COPY distro /nessus-didcomm

ENV NESSUS_HOME="/nessus-didcomm"

WORKDIR "/nessus-didcomm"

ENTRYPOINT ["./bin/didcomm.sh"]
