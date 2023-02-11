## Nessus DidComm RFC0023: DID Exchange 2.0

Related:
* [Aries RFC0023: DID Exchange 1.0][rfc0023]
* [DIDComm V2: DIDComm Encrypted Messages][dcv2-encrypted-msg]

### Summary

This RFC describes the protocol to exchange DIDs between agents when establishing a DID based relationship.

### Motivation

Demonstrate the use of [encrypted][dcv2-encrypted-msg] DIDComm V2 messages 
with the [Aries RFC0023: DID Exchange 1.0][rfc0023] protocol 

### Message Details

#### Requester (Alice) creates DidEx Request

Here we show the plain DidEx Request message with an attached Did Document.
On the wire, this message is signed and encrypted 

```json
{
  "id": "155329d6-a779-47a3-a9ab-bf58eb70888c",
  "typ": "application/didcomm-plain+json",
  "type": "https://didcomm.org/didexchange/2.0-Alpha/request",
  "from": "did:key:z6MktFkWEt4sBjanDVwgbgVnLrK85uextK3CHHnRqUPh93eq",
  "to": [
    "did:key:z6MksfNuvpjws3ucrLwk7mHVwaSunW92Rj62KvGJgzkvkymt"
  ],
  "body": {
    "accept": [
      "didcomm/v2"
    ]
  },
  "attachments": [
    {
      "id": "9dd91144-7b0f-4579-b127-953bad8d2a0a",
      "data": {
        "json": {
          "did": "did:key:z6MktFkWEt4sBjanDVwgbgVnLrK85uextK3CHHnRqUPh93eq",
          "keyAgreements": [
            "did:key:z6MktFkWEt4sBjanDVwgbgVnLrK85uextK3CHHnRqUPh93eq#key-x25519-1"
          ],
          "authentications": [
            "did:key:z6MktFkWEt4sBjanDVwgbgVnLrK85uextK3CHHnRqUPh93eq#key-1"
          ],
          "verificationMethods": [
            {
              "id": "did:key:z6MktFkWEt4sBjanDVwgbgVnLrK85uextK3CHHnRqUPh93eq#key-1",
              "type": "JSON_WEB_KEY_2020",
              "verificationMaterial": {
                "format": "JWK",
                "value": "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"zRDTlA2L6zNZmmVkn6U_A6y2N2UH4b8-gwrP-CKO1Ro\"}"
              },
              "controller": "did:key:z6MktFkWEt4sBjanDVwgbgVnLrK85uextK3CHHnRqUPh93eq#key-1"
            },
            {
              "id": "did:key:z6MktFkWEt4sBjanDVwgbgVnLrK85uextK3CHHnRqUPh93eq#key-x25519-1",
              "type": "JSON_WEB_KEY_2020",
              "verificationMaterial": {
                "format": "JWK",
                "value": "{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"p4CHCDXfUD0UGB8-ZxDvMjjFfmALQgTALzISKxMKdSg\"}"
              },
              "controller": "did:key:z6MktFkWEt4sBjanDVwgbgVnLrK85uextK3CHHnRqUPh93eq#key-x25519-1"
            }
          ],
          "didCommServices": [
            {
              "id": "did:key:z6MktFkWEt4sBjanDVwgbgVnLrK85uextK3CHHnRqUPh93eq#didcomm-1",
              "serviceEndpoint": "http://192.168.0.10:8130",
              "accept": [
                "didcomm/v2"
              ]
            }
          ]
        }
      },
      "media_type": "application/did+json"
    }
  ],
  "thid": "155329d6-a779-47a3-a9ab-bf58eb70888c",
  "pthid": "326138c9-d6c2-43c3-ad42-49acf62ab263"
}
```

#### Responder (Acme) creates DidEx Response

Here we show the plain DidEx Response message with an attached Did Document.
On the wire, this message is signed and encrypted

```json
{
  "id": "0e1c81be-a142-4184-8195-a5a3dcac7136",
  "typ": "application/didcomm-plain+json",
  "type": "https://didcomm.org/didexchange/2.0-Alpha/response",
  "from": "did:key:z6MknkFvrpVD7oQXSw6bxQQSqmLy4Woj7Yk7ToXpHcYMCdua",
  "to": [
    "did:key:z6MktFkWEt4sBjanDVwgbgVnLrK85uextK3CHHnRqUPh93eq"
  ],
  "body": {
    "accept": [
      "didcomm/v2"
    ]
  },
  "attachments": [
    {
      "id": "8be070cc-26e1-4a4c-a41e-5057e92ed2e3",
      "data": {
        "json": {
          "did": "did:key:z6MknkFvrpVD7oQXSw6bxQQSqmLy4Woj7Yk7ToXpHcYMCdua",
          "keyAgreements": [
            "did:key:z6MknkFvrpVD7oQXSw6bxQQSqmLy4Woj7Yk7ToXpHcYMCdua#key-x25519-1"
          ],
          "authentications": [
            "did:key:z6MknkFvrpVD7oQXSw6bxQQSqmLy4Woj7Yk7ToXpHcYMCdua#key-1"
          ],
          "verificationMethods": [
            {
              "id": "did:key:z6MknkFvrpVD7oQXSw6bxQQSqmLy4Woj7Yk7ToXpHcYMCdua#key-1",
              "type": "JSON_WEB_KEY_2020",
              "verificationMaterial": {
                "format": "JWK",
                "value": "{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"ezg86VNTSzA-Y3NRphHe55whJ4o5vzt-U9Kfnnd37hE\"}"
              },
              "controller": "did:key:z6MknkFvrpVD7oQXSw6bxQQSqmLy4Woj7Yk7ToXpHcYMCdua#key-1"
            },
            {
              "id": "did:key:z6MknkFvrpVD7oQXSw6bxQQSqmLy4Woj7Yk7ToXpHcYMCdua#key-x25519-1",
              "type": "JSON_WEB_KEY_2020",
              "verificationMaterial": {
                "format": "JWK",
                "value": "{\"kty\":\"OKP\",\"crv\":\"X25519\",\"x\":\"5XZhq172KYpPLylym_VDG5pIGK9Pwoo96kyTyL049lI\"}"
              },
              "controller": "did:key:z6MknkFvrpVD7oQXSw6bxQQSqmLy4Woj7Yk7ToXpHcYMCdua#key-x25519-1"
            }
          ],
          "didCommServices": [
            {
              "id": "did:key:z6MknkFvrpVD7oQXSw6bxQQSqmLy4Woj7Yk7ToXpHcYMCdua#didcomm-1",
              "serviceEndpoint": "http://192.168.0.10:8130",
              "accept": [
                "didcomm/v2"
              ]
            }
          ]
        }
      },
      "media_type": "application/did+json"
    }
  ],
  "thid": "155329d6-a779-47a3-a9ab-bf58eb70888c",
  "pthid": "326138c9-d6c2-43c3-ad42-49acf62ab263"
}
```

#### Requester (Alice) sends DidEx Complete

Here we show the plain DidEx Complete message with an attached Did Document.
On the wire, this message is signed and encrypted

```json
{
  "id": "1394c73b-811b-4f4d-9660-52f06496fb53",
  "typ": "application/didcomm-plain+json",
  "type": "https://didcomm.org/didexchange/2.0-Alpha/complete",
  "from": "did:key:z6MktFkWEt4sBjanDVwgbgVnLrK85uextK3CHHnRqUPh93eq",
  "to": [
    "did:key:z6MknkFvrpVD7oQXSw6bxQQSqmLy4Woj7Yk7ToXpHcYMCdua"
  ],
  "body": {},
  "thid": "155329d6-a779-47a3-a9ab-bf58eb70888c",
  "pthid": "326138c9-d6c2-43c3-ad42-49acf62ab263"
}
```

[dcv2-encrypted-msg]: https://identity.foundation/didcomm-messaging/spec/#c3-didcomm-encrypted-messages
[rfc0023]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
