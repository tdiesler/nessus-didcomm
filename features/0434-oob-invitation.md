## Nessus DidComm RFC0434: Out-of-Band Invitation 2.0

Related:
* [DIDComm V2: Out Of Band Messages][dcv2-oob]
* [Aries RFC0434: Out-of-Band Protocol 1.1][rfc0434]

### Summary

The Out-of-band protocol is used when you wish to engage with another agent and you don't have a DIDComm connection to use for the interaction.

### Motivation

DIDComm V2 talks about [out-of-band invitations][dcv2-oob] and suggests to use an array attachments to specify invitation detail. 

> An array of attachments that will contain the invitation messages in order of preference that the receiver can use in responding to the message.

Leaving out such details would work when the inviter uses a public DID for the invitation. Such DID can then be resolved and actual connection
details be found in the associated DID Document.

Here, we define a simple alternative that allows us to embed such connection details in the DIDComm Invitation message.
Specifically, we borrow the content from the `services` section in [Aries RFC0434][rfc0434] and use it as attachments. 

### Message Details

```json
{
    "id":"32e08e73-70a1-4d72-a569-bd40f427eb05",
    "typ":"application/didcomm-plain+json",
    "type":"https://didcomm.org/out-of-band/2.0/invitation",
    "from":"did:key:z6MktCV3oT37A3GhPx36rXXEh6LJhL7dhH6eSfjwDk3YYwWZ",
    "body":{
        "accept":[
            "didcomm/v2",
            "didcomm/aip2;env\u003drfc587"
        ]
    },
    "attachments":[
        {
            "id":"293034ff-5fc5-42a4-805a-122cecf08c76",
            "data":{
                "json":{
                    "id":"#inline",
                    "type":"did-communication",
                    "recipientKeys":[
                        "did:key:z6MktCV3oT37A3GhPx36rXXEh6LJhL7dhH6eSfjwDk3YYwWZ"
                    ],
                    "serviceEndpoint":"http://192.168.0.10:8130"
                }
            }
        }
    ]
}
```

[dcv2-oob]: https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages
[rfc0434]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0434-outofband
