## Nessus DidComm Features

> The purpose of DIDComm Messaging is to provide a secure, private communication methodology built atop the decentralized design of DIDs.

As a [framework or methodology][dcv2-purpose] DIDComm Messaging enables higher-order protocols, but does not necessarily define these.

Here we define a set of (very) basic protocols that can get us started with DIDComm Messaging. Over time, these protocols are 
expected to get replaced by standards from the DIDComm Messaging space that allow actual agent-to-agent interoperability.

| Protocol                                        | AcaPy | Nessus |
|:------------------------------------------------|:-----:|:------:|
| [RFC0023 DID Exchange Protocol 2.0][rfc0023v2]  |       |   x    |
| [RFC0095 Basic Message 2.0][rfc0095v2]          |       |   x    |
| [RFC0434 Out-of-Band Protocol 2.0][rfc0434v2]   |       |   x    |

[dcv2-purpose]: https://identity.foundation/didcomm-messaging/spec/#purpose-and-scope
[rfc0023v2]: ./0023-did-exchange.md
[rfc0095v2]: ./0095-basic-message.md
[rfc0434v2]: ./0434-oob-invitation.md
