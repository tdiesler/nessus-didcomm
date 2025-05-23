
# EBSI OpenID4VC and Wallet Proxy 

1. Generate a Self-Signed TLS Certificate and Key
2. Package Cert + Key into a .p12 Keystore
3. Add the Cert to the JVM Truststore (cacerts) for Client Trust

```
openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
  -keyout oid4vc/tls/ebsi.key -out oid4vc/tls/ebsi.crt -days 365 \
  -subj "/CN=localhost/O=Nessus/C=US"

openssl pkcs12 -export \
  -in oid4vc/tls/ebsi.crt \
  -inkey oid4vc/tls/ebsi.key \
  -out oid4vc/tls/keystore.p12 \
  -name ebsi.localhost \
  -passout pass:changeit

sudo keytool -cacerts -importcert \
  -alias ebsi.localhost \
  -file oid4vc/tls/ebsi.crt \
  -storepass changeit \
  -noprompt

sudo keytool -cacerts -delete \
  -alias ebsi.localhost \
  -storepass changeit
```