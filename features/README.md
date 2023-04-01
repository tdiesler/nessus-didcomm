## Nessus DidComm Features

> The purpose of DIDComm Messaging is to provide a secure, private communication methodology built atop the decentralized design of DIDs.

As a [framework or methodology][dcv2-purpose] DIDComm Messaging enables higher-order protocols, but does not necessarily define these.

Here we define a set of (very) basic protocols that can get us started with DIDComm Messaging. Over time, these protocols are 
expected to get replaced by standards from the DIDComm Messaging space that allow actual agent-to-agent interoperability.

| Protocol                                      | Nessus |
|:----------------------------------------------|:------:|
| [Trust Ping 2.0][rfc0048v2]                   |   x    |
| [Basic Message 2.0][rfc0095v2]                |   x    |
| [Out-of-Band Protocol 2.0][rfc0434v2]         |   x    |
| [Issue Credential 3.0][waci-issue-vc-v3]      |   x    |
| [Present Proof 3.0][waci-present-vp-v3]       |   x    |
| [RFC0317 Please ACK][rfc0317]                 |        |
| [RFC0015 ACKs][rfc0015]                       |        |
| [Report Problem 2.0][dcv2-problem]            |        |

[dcv2-problem]: https://identity.foundation/didcomm-messaging/spec/#problem-reports
[rfc0015]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0015-acks
[rfc0317]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0317-please-ack
[rfc0048v2]: features/0048-trust-ping
[rfc0095v2]: features/0095-basic-message
[rfc0434v2]: features/0434-oob-invitation
[waci-issue-vc-v3]: https://github.com/decentralized-identity/waci-didcomm/tree/main/issue_credential
[waci-present-vp-v3]: https://github.com/decentralized-identity/waci-didcomm/blob/main/present_proof/present-proof-v3.md
