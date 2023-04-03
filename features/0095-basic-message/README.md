## Nessus DidComm: Basic Message 2.0

Related:
* [Aries RFC0095: Basic Message Protocol 1.0][rfc0095]
* [DIDComm V2: DIDComm Plaintext Messages][dcv2-plain-msg]
* [DIDComm V2: DIDComm Signed Messages][dcv2-signed-msg]
* [DIDComm V2: DIDComm Encrypted Messages][dcv2-encrypted-msg]

### Summary

The BasicMessage protocol describes a stateless, easy to support user message protocol. 
It has a single message type used to communicate.

### Motivation

Demonstrate the use of [plain][dcv2-plain-msg], [signed][dcv2-signed-msg] and [encrypted][dcv2-encrypted-msg] DIDComm V2 message

### Message Details

```json
{
    "id":"13fa75fb-c6cf-4a8b-a549-2207cd31ddcb",
    "typ":"application/didcomm-plain+json",
    "type":"https://didcomm.org/basicmessage/2.0/message",
    "from":"did:key:z6MkorRGtXqsPnD3bwqT6wGbNJDCEeD9zY1DfbnEPkkzFLDz",
    "to":[
        "did:key:z6MksVz8urciusNUhE8SS2BxT3S6fUHJVwbcja6fMb9qBNZX"
    ],
    "created_time":1676295686,
    "body":{
        "content":"Your hovercraft is full of eels"
    }
}
```

[dcv2-plain-msg]: https://identity.foundation/didcomm-messaging/spec/#plaintext-message-structure
[dcv2-signed-msg]: https://identity.foundation/didcomm-messaging/spec/#c2-didcomm-signed-messages
[dcv2-encrypted-msg]: https://identity.foundation/didcomm-messaging/spec/#c3-didcomm-encrypted-messages
[rfc0095]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0095-basic-message
