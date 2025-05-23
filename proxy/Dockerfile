FROM eclipse-temurin:21

ARG PROJECT_VERSION

COPY ./target/nessus-identity-proxy-*.jar /ebsi/nessus-identity-proxy.jar

WORKDIR /ebsi

ENTRYPOINT ["java", "-jar", "nessus-identity-proxy.jar"]
