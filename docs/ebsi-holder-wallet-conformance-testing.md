# Holder Wallet Conformance Testing

https://hub.ebsi.eu/wallet-conformance
https://hub.ebsi.eu/wallet-conformance/holder-wallet
https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows

## Prerequisite

Create did:key:jwk_jcs-pub identifier from ES256 key algorithm

* Generate key through dev-wallet with {"keyType": "secp256r1"}

## Insert your DID and Credential Offer Endpoint

Leave Credential Offer Endpoint: openid-credential-offer://

## Initiate Credential Issuance - Cross Device

QR reading capabilities: No

### In-time Credential

Clicking on 'Initiate (credential offering redirect)' opens a new tab that receives a redirect like this ...

```
openid-credential-offer://?credential_offer_uri=https%3A%2F%2Fapi-conformance.ebsi.eu%2Fconformance%2Fv3%2Fissuer-mock%2Foffers%2F56c4c127-384d-4e4a-8aba-26bdf9076fac
```

https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/initiate-credential-offer?credential_type=CTWalletSameAuthorisedInTime&client_id=did%3Akey%3Az2dmzD81cgPx8Vki7JbuuMmFYrWPgYoytykUZ3eyqht1j9KbsJG52H2i5BdDcy611DWnWUKbAhxwPU2Jduj6CJ7PVaZ8ajCpsndd8u8FhDBuhrEoYxFpHeTbGSAQ8fshdhHKvNqqVEJW2wFPSTG3cRxqQwdkeNSBZ1yLXpyK6uwjfu5Moa&credential_offer_endpoint=openid-credential-offer%3A%2F%2F