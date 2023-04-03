## Nessus DidComm: Out-of-Band Invitation 2.0

Related:
* [Aries RFC0434: Out-of-Band Protocol 1.1][rfc0434]
* [DIDComm V2: Out Of Band Messages][dcv2-oob]
* [Support DID initialState query parameter][nghi67]

### Summary

The Out-of-band protocol is used when you wish to engage with another agent and you don't have a DIDComm connection to use for the interaction.

### Motivation

DIDComm V2 talks about [out-of-band invitations][dcv2-oob] and suggests to use an array attachments to specify invitation detail. 

> An array of attachments that will contain the invitation messages in order of preference that the receiver can use in responding to the message.

Leaving out such details would work when the inviter uses a public DID for the invitation. Such DID can then be resolved and actual connection
details be found in the associated DID Document.

Here, we define a simple alternative that allows us to embed such connection details in the DIDComm Invitation message.
Specifically, we create a Did Document for the invitation key and attach that to the invitation message.

Later, when we receive the first (Trust Ping) message from the Invitee, we rotate the Inviter Did and publish a new Did Document
The first Trust Ping Response, will use `fromPrior` to maintain trust integrity. 

### Message Details

```json
{
  "id":"a1f1a14e-5b50-40fa-a1b2-05fef7a096ce",
  "typ":"application/didcomm-plain+json",
  "type":"https://didcomm.org/out-of-band/2.0/invitation",
  "from":"did:key:z6MksUtmw8WmEVzL7xiQF7PuMu4mC2cavyU9jbQ4VoBSA6EN",
  "body":{
    "accept":[
      "didcomm/v2"
    ]
  },
  "attachments":[
    {
      "id":"f5621355-bc94-443a-9a90-ae635c6f0784",
      "media_type":"application/did+json",
      "data":{
        "jws":null,
        "hash":null,
        "json":{
          "did":"did:key:z6MksUtmw8WmEVzL7xiQF7PuMu4mC2cavyU9jbQ4VoBSA6EN",
          "keyAgreements":[
            "did:key:z6MksUtmw8WmEVzL7xiQF7PuMu4mC2cavyU9jbQ4VoBSA6EN#key-x25519-1"
          ],
          "authentications":[
            "did:key:z6MksUtmw8WmEVzL7xiQF7PuMu4mC2cavyU9jbQ4VoBSA6EN#key-1"
          ],
          "verificationMethods":[
            {
              "id":"did:key:z6MksUtmw8WmEVzL7xiQF7PuMu4mC2cavyU9jbQ4VoBSA6EN#key-1",
              "type":"JSON_WEB_KEY_2020",
              "verificationMaterial":{
                "format":"JWK",
                "value":"{
                \"kty\":\"OKP\",
                \"crv\":\"Ed25519\",
                \"x\":\"wZMKqZVWlVMpoMKCdMxj-zdjldgo4QPC6RYo7tHupXM\"
              }"
            },
            "controller":"did:key:z6MksUtmw8WmEVzL7xiQF7PuMu4mC2cavyU9jbQ4VoBSA6EN#key-1"
            },
            {
              "id":"did:key:z6MksUtmw8WmEVzL7xiQF7PuMu4mC2cavyU9jbQ4VoBSA6EN#key-x25519-1",
              "type":"JSON_WEB_KEY_2020",
              "verificationMaterial":{
                "format":"JWK",
                "value":"{
                \"kty\":\"OKP\",
                \"crv\":\"X25519\",
                \"x\":\"SmoEUVqd9dfYEpwViLcRvdnhcu3b43huK2Kp1wKhcxY\"
              }"
            },
            "controller":"did:key:z6MksUtmw8WmEVzL7xiQF7PuMu4mC2cavyU9jbQ4VoBSA6EN#key-x25519-1"
            }
          ],
          "didCommServices":[
            {
              "id":"did:key:z6MksUtmw8WmEVzL7xiQF7PuMu4mC2cavyU9jbQ4VoBSA6EN#didcomm-1",
              "serviceEndpoint":"http://192.168.0.10:9000",
              "accept":[
                "didcomm/v2"
              ]
            }
          ]
        }
      }
    }
  ]
}
```

[dcv2-oob]: https://didcomm.org/out-of-band/2.0
[rfc0434]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0434-outofband
[nghi67]: https://github.com/tdiesler/nessus-didcomm/issues/67
