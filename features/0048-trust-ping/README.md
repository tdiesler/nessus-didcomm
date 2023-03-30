## Nessus DidComm: Trust Ping 2.0

Related:
* [Aries RFC0048: Trust Ping Protocol 1.0][rfc0048]
* [DIDComm V2: DIDComm Encrypted Messages][dcv2-encrypted-msg]

### Summary

Describe a standard way for agents to test connectivity, responsiveness, and security of a pairwise channel.

### Motivation

Demonstrate the use of [encrypted][dcv2-encrypted-msg] DIDComm V2 message from Trust Ping semantics

### Message Details

#### Sender (Alice) creates TrustPing

On the wire, the Trust Ping message is signed and encrypted
Note, the first Trust Ping may contain a Did Document attachment for the Invitee

```json
{
  "id": "fb05b5e9-7ea7-4f3c-9f14-5477fde333c0",
  "typ": "application/didcomm-plain+json",
  "type": "https://didcomm.org/trust_ping/2.0-preview/ping",
  "from": "did:key:z6Mkp8u4BGkJLBQXKcCESCcGPzuASc5GA4bLYQzt5YYHdF4D",
  "to": [
    "did:key:z6MkmwFcA1vt4BtHv4rDyhRSCG5T3HxsLXAxLNKGY9NjnNME"
  ],
  "created_time": 1676104455,
  "expires_time": 1676190855,
  "body": {
    "comment": "Ping from Alice"
  }
}
```

#### Receiver (Acme) creates TrustPing Response

On the wire, the Trust Ping Response message is signed and encrypted
Note, a Trust Ping Response may use `fromPrior` to communicate a change of recipient Did

```json
{
  "id": "a08ec5d2-2f75-4190-8239-5a87b0fbe860",
  "typ": "application/didcomm-plain+json",
  "type": "https://didcomm.org/trust_ping/2.0-preview/ping_response",
  "from": "did:key:z6MkmwFcA1vt4BtHv4rDyhRSCG5T3HxsLXAxLNKGY9NjnNME",
  "to": [
    "did:key:z6Mkp8u4BGkJLBQXKcCESCcGPzuASc5GA4bLYQzt5YYHdF4D"
  ],
  "created_time": 1676104455,
  "expires_time": 1676190855,
  "body": {
    "comment": "Pong from Acme"
  },
  "thid": "fb05b5e9-7ea7-4f3c-9f14-5477fde333c0"
}
```

[dcv2-encrypted-msg]: https://identity.foundation/didcomm-messaging/spec/#c3-didcomm-encrypted-messages
[rfc0048]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0048-trust-ping
