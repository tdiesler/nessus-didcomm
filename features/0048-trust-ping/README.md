## Nessus DidComm: Trust Ping 2.0

Related:
* [Trust Ping 2.0][dcv2-trust-ping]
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
  "id":"4d6b6d9b-f6ea-4df4-82f5-fe4b3b07c37b",
  "type":"https://didcomm.org/trust-ping/2.0/ping",
  "from":"did:peer:2.Ez6LSg9htFVk4qAuYs17jDEAhhHCx8WqdMTuzhjZ98uVSDa5C.Vz6MkgqCUy43arZurXPMC1q3yHBbN1E1q1e6rDvzbw8pJz8iD.SeyJ0IjoiZG0iLCJzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIn0",
  "to":[
    "did:peer:2.Ez6LSndYoiE8pUsWL88uZjvL1g111gvFAZCp74hJBUWG5QoRt.Vz6MktexTRqDqUqkjLYBzjFB2pKXDQUf9TVUoDNEnN6nt7fZb.SeyJ0IjoiZG0iLCJzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIn0"
  ],
  "created_time":1680583120,
  "expires_time":1680669520,
  "body":{
    "comment":"Ping from Alice",
    "response_requested":true
  }
}
```

#### Receiver (Acme) creates TrustPing Response

On the wire, the Trust Ping Response message is signed and encrypted
Note, a Trust Ping Response may use `fromPrior` to communicate a change of recipient Did

```json
{
    "id":"40fbdb36-f75f-43f6-ad84-610af6a96b3c",
    "thid":"4d6b6d9b-f6ea-4df4-82f5-fe4b3b07c37b",
    "type":"https://didcomm.org/trust-ping/2.0/ping-response",
    "from":"did:peer:2.Ez6LSgjK6Ud6LWB5gQNBVBxJ2qa9674Tud6orKZeGxH88yH1d.Vz6MkmceKVRBgkx61ejte9iY1R9NauHcjike8xQuJS6NhLsVC.SeyJ0IjoiZG0iLCJzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIn0",
    "to":[
        "did:peer:2.Ez6LSg9htFVk4qAuYs17jDEAhhHCx8WqdMTuzhjZ98uVSDa5C.Vz6MkgqCUy43arZurXPMC1q3yHBbN1E1q1e6rDvzbw8pJz8iD.SeyJ0IjoiZG0iLCJzIjoiaHR0cDovL2xvY2FsaG9zdDo5MDAwIn0"
    ],
    "created_time":1680583120,
    "expires_time":1680669520,
    "body":{
        "comment":"Pong from Faber"
    }
}
```

[dcv2-encrypted-msg]: https://identity.foundation/didcomm-messaging/spec/#c3-didcomm-encrypted-messages
[dcv2-trust-ping]: https://identity.foundation/didcomm-messaging/spec/#trust-ping-protocol-20
