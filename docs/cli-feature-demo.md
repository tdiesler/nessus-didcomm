## Nessus DIDComm CLI

The Nessus DIDComm CLI provides access to agent functionality from the command line. 

Here, a (possibly non-exhaustive) list of stuff you can do ...

* manage multitenant wallet state
* create and receive invitations
* establish peers connections  
* work with supported protocols
* examine message details
* etc.

### Run the CLI and get help 

```shell
$ .../distro/bin/didcomm.sh

Nessus DIDComm CLI
Version: 1.0

>> help
  System:
    exit     exit from app/script
    help     command help
  Commands:
    agent    Agent related commands
    clear    Clear the terminal screen
    commands Show tree of available commands
    rfc0023  RFC0023 Did Exchange
    rfc0048  RFC0048 Trust Ping
    rfc0095  RFC0095 Basic Message
    rfc0434  RFC0434 Out-of-Band Invitation
    wallet   Multitenant wallet commands
```

Help shows a number of top-level commands. 

Help on Subcommands, Options and Parameters can be obtained like this ...

```shell
>> wallet help
Usage: didcomm wallet [-qv] [--all] [--alias=<alias>] [COMMAND]
Multitenant wallet commands
      --alias=<alias>   Optional wallet alias
      --all             Flag to show all wallets
  -q, --quiet           Suppress terminal output
  -v, --verbose         More verbose terminal output
Commands:
  create      Create a wallet for a given agent
  remove      Remove and delete a given wallet
  connection  Show available connections and their details
  did         Show available Dids and their details
  invitation  Show available invitations and their details
  messages    Show connection related messages
  switch      Switch the current context wallet
```

### Work with multitenant wallets  

On startup, the CLI examines the current environment and loads the state of already existing wallets it can find

Here we have two AcaPy wallets that are currently online 

```shell
>> wallet
Faber [agent=AcaPy, url=http://192.168.0.10:8031]
Government [agent=AcaPy, url=http://192.168.0.10:8031]
```

#### Create Alice's wallet

A wallet is associated with one of many supported agent types - above, we see two AcaPy wallets. 
Lets now create a native Nessus wallet for Alice

```shell
>> wallet create --name Alice
Wallet created: Alice [agent=Nessus, url=http://192.168.0.10:8130]

Alice>>
```

The prompt now changes to indicate that the current context wallet is Alice's

In case we want to issue multiple commands in the context of another wallet, we can switch to it.
Alternatively, we can stay with Alice and explicitly name the wallet for a given command 

```shell
>> wallet switch fab

Faber>>
```

The CLI supports command/option completion with TAB and command history with UP/DOWN.
An element selection alias (in this case for a wallet) can be abbreviated and case-ignorant

### Agent Endpoints

Every wallet has a public HTTP endpoint - multiple wallets may share the same endpoint.

For Nessus wallets, the CLI can start/stop these endpoints individually. This is useful, when 
we want to simulate an agent becoming unreachable. Also, wallets may want to use different processes/memory

Lets now start Alice's HTTP endpoint

```shell
Alice>> agent start
Started Camel endpoint on 192.168.0.10:8130
```

As you can see, this starts an [Apache Camel](https://camel.apache.org) endpoint, and hence provides a plethora of routing 
transformation and other processing possibilities for incoming DIDComm messages. 

### RFC0434: Out-of-Band Invitation

The CLI can support many protocols in multiple versions. This is useful for scripting various interoperability scenarios.

Let's start with the classic case of Faber College inviting Alice to have a peer connection to then exchange higher level 
DIDComm messages.

```shell
Alice>> rfc0434 create-invitation --inviter faber
Faber created an RFC0434 Invitation: [key=6sNdrxQsrYPpT4nZReAxDJViMA3PXcFeNpfS4hebpUFq, url=http://192.168.0.10:8030]

Alice>> rfc0434 receive-invitation 
Alice received an RFC0434 Invitation: [key=6sNdrxQsrYPpT4nZReAxDJViMA3PXcFeNpfS4hebpUFq, url=http://192.168.0.10:8030] ... [Invi:6sNdrxQ]
```

On the right we see the current context invitation alias, which will be used in case we leave out the explicit command option for it. 

Let's do this again with more geeky options ...

```shell
Alice>> rfc0434 create-invitation --inviter faber --verbose
Faber created an RFC0434 Invitation: 
{
    "@id":"75ba9adc-d416-4d96-9955-cad456024ce3",
    "@type":"https://didcomm.org/out-of-band/1.1/invitation",
    "label":"Invitation from Faber",
    "accept":[
        "didcomm/v2"
    ],
    "handshake_protocols":[
        "https://didcomm.org/didexchange/1.0"
    ],
    "services":[
        {
            "id":"#inline",
            "type":"did-communication",
            "recipientKeys":[
                "did:key:z6MkhEpx5hfac5qR6CuwTvHVR6tBtBD8HGWPYVA2teP48yv8"
            ],
            "serviceEndpoint":"http://192.168.0.10:8030"
        }
    ],
    "state":"initial"
}
```

Even more interesting, Acme could invite Alice using DIDComm V2

```shell
Alice>> wallet create --name Acme
Wallet created: Acme [agent=Nessus, url=http://192.168.0.10:8130]

Acme>> rfc0434 create-invitation --verbose --dcv2
Acme created an RFC0434 Invitation: 
{
    "id":"8180da5f-043c-4d2c-b46a-425ea8b78af3",
    "typ":"application/didcomm-plain+json",
    "type":"https://didcomm.org/out-of-band/2.0-preview/invitation",
    "from":"did:key:z6MkwAxfM32RTU5CJgFFgE38gznHSxjYZGsPuJ7xvGTzCmbQ",
    "body":{
        "accept":[
            "didcomm/v2"
        ]
    },
    "attachments":[
        {
            "id":"e4409e62-72ba-4ec2-ae58-e3d7cc347189",
            "data":{
                "json":{
                    "did":"did:key:z6MkwAxfM32RTU5CJgFFgE38gznHSxjYZGsPuJ7xvGTzCmbQ",
                    "keyAgreements":[
                        "did:key:z6MkwAxfM32RTU5CJgFFgE38gznHSxjYZGsPuJ7xvGTzCmbQ#key-x25519-1"
                    ],
                    "authentications":[
                        "did:key:z6MkwAxfM32RTU5CJgFFgE38gznHSxjYZGsPuJ7xvGTzCmbQ#key-1"
                    ],
                    "verificationMethods":[
                        {
                            "id":"did:key:z6MkwAxfM32RTU5CJgFFgE38gznHSxjYZGsPuJ7xvGTzCmbQ#key-1",
                            "type":"JSON_WEB_KEY_2020",
                            "verificationMaterial":{
                                "format":"JWK",
                                "value":"{
                                    \"kty\":\"OKP\",
                                    \"crv\":\"Ed25519\",
                                    \"x\":\"-Gm6q189MdH-x2tg2kUCEPGN-DMDMpiPKqrlm-97ZcM\"
                                }"
                            },
                            "controller":"did:key:z6MkwAxfM32RTU5CJgFFgE38gznHSxjYZGsPuJ7xvGTzCmbQ#key-1"
                        },
                        {
                            "id":"did:key:z6MkwAxfM32RTU5CJgFFgE38gznHSxjYZGsPuJ7xvGTzCmbQ#key-x25519-1",
                            "type":"JSON_WEB_KEY_2020",
                            "verificationMaterial":{
                                "format":"JWK",
                                "value":"{
                                    \"kty\":\"OKP\",
                                    \"crv\":\"X25519\",
                                    \"x\":\"nzr0w2G8L-EFcd5gjcc5hLBa1F-o5mlfJ1e6wbP1SSY\"
                                }"
                            },
                            "controller":"did:key:z6MkwAxfM32RTU5CJgFFgE38gznHSxjYZGsPuJ7xvGTzCmbQ#key-x25519-1"
                        }
                    ],
                    "didCommServices":[
                        {
                            "id":"did:key:z6MkwAxfM32RTU5CJgFFgE38gznHSxjYZGsPuJ7xvGTzCmbQ#didcomm-1",
                            "serviceEndpoint":"http://192.168.0.10:8130",
                            "accept":[
                                "didcomm/v2"
                            ]
                        }
                    ]
                }
            },
            "media_type":"application/did+json"
        }
    ]
}
```

The message above follows the general layout for [DIDComm V2 Out-of-Band](https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages) messages.
However, the spec unfortunately or purposefully leaves out the specifics of a DIDComm peer-to-peer Invitation.

In such cases, Nessus makes a number of assumptions for this [POC](https://github.com/tdiesler/nessus-didcomm/blob/main/docs/proof-of-concept.md) implementation.
These Nessus preview protocols are documented [here](https://github.com/tdiesler/nessus-didcomm/tree/main/features).

Generally, everything we demonstrate with Faber-Alice (i.e. AcaPy/Nessus) is also available in it's DIDComm V2 variant for Acme-Alice
In future, when DIDComm V2 becomes available in AcaPy, we expect message content and type URI to change and reflect official standards.

In this case, a Nessus DidComm RFC0434 Invitation message has a Did Document attached that the Invitee can use to establish a peer connection with the Inviter

### RFC0023: DID Exchange

After Alice received the Invitation from Faber, she can request a peer connection

```shell
Alice>> rfc0434 receive-invitation 
Alice received an RFC0434 Invitation: [key=9W5hwWWGP3fqpbde6tcYuUGFWg6y1bHpt2TpamnVddib, url=http://192.168.0.10:8030]

Alice>> rfc0023 connect -v
{
    "id":"e257ce4f-ccfe-42af-9cd3-7fbd530538bf",
    "agent":"Nessus",
    "invitationKey":"9W5hwWWGP3fqpbde6tcYuUGFWg6y1bHpt2TpamnVddib",
    "myRole":"REQUESTER",
    "myLabel":"Invitee Alice on NESSUS",
    "myEndpointUrl":"http://192.168.0.10:8130",
    "theirRole":"RESPONDER",
    "theirLabel":"Inviter Faber on ACAPY",
    "theirEndpointUrl":"http://192.168.0.10:8030",
    "state":"ACTIVE",
    "myDid":{
        "method":"SOV",
        "algorithm":"EdDSA_Ed25519",
        "verkey":"8CZ4e8VNhRh2YE3dfKH6TMeGWawz2H3Vw5Cjo1f6nua6",
        "id":"ED73PijFhncYuLx3rHrUCC"
    },
    "theirDid":{
        "method":"SOV",
        "algorithm":"EdDSA_Ed25519",
        "verkey":"9ZZXMZSXoT6q7DYHr8jVpDkwPuPHC84c6Wv2AhpAbUiq",
        "id":"Gi4hghe8LzKCfHRFnSauL1"
    }
}
```

Above, Alice uses the context invitation, which must also be found in her wallet. The --verbose flag indicates that
we want to see the connection details.

Nessus records the messages that are being exchanged, which we can now look at

```shell
Alice>> wallet messages 
Messages:
[id=e2d8996f-6670-4205-83a6-c8b41a38885d, thid=e2d8996f-6670-4205-83a6-c8b41a38885d, type=https://didcomm.org/out-of-band/1.1/invitation]
[id=80890d4c-c03a-400d-84ab-639fecaf40ff, thid=80890d4c-c03a-400d-84ab-639fecaf40ff, type=https://didcomm.org/didexchange/1.0/request]
[id=ac3fb8f1-3e65-4c5b-9e0f-ee393a9ad83c, thid=80890d4c-c03a-400d-84ab-639fecaf40ff, type=https://didcomm.org/didexchange/1.0/response]
[id=566c9916-e415-4fe3-8e8d-12b8e481f7ae, thid=80890d4c-c03a-400d-84ab-639fecaf40ff, type=https://didcomm.org/didexchange/1.0/complete]
[id=4d653bf5-cfe6-4d85-8335-bf0ed3832e79, thid=4d653bf5-cfe6-4d85-8335-bf0ed3832e79, type=https://didcomm.org/trust_ping/1.0/ping]
[id=a589fa85-10ec-45ef-b371-eaab47144941, thid=4d653bf5-cfe6-4d85-8335-bf0ed3832e79, type=https://didcomm.org/trust_ping/1.0/ping_response]
```

For example, Faber's response would look like this ...

```shell
Alice>> wallet messages --msg=ac3fb --verbose
Messages:
EndpointMessage(
    headers={
        MessageId=ac3fb8f1-3e65-4c5b-9e0f-ee393a9ad83c,
        MessageParentThid=e2d8996f-6670-4205-83a6-c8b41a38885d,
        MessageProtocolUri=https://didcomm.org/didexchange/1.0,
        MessageRecipientVerkey=8CZ4e8VNhRh2YE3dfKH6TMeGWawz2H3Vw5Cjo1f6nua6,
        MessageSenderVerkey=9ZZXMZSXoT6q7DYHr8jVpDkwPuPHC84c6Wv2AhpAbUiq,
        MessageThid=80890d4c-c03a-400d-84ab-639fecaf40ff,
        MessageType=https://didcomm.org/didexchange/1.0/response
    },
    body={
        "@type": "https://didcomm.org/didexchange/1.0/response",
        "@id": "ac3fb8f1-3e65-4c5b-9e0f-ee393a9ad83c",
        "~thread": {
            "thid": "80890d4c-c03a-400d-84ab-639fecaf40ff",
            "pthid": "e2d8996f-6670-4205-83a6-c8b41a38885d"
        },
        "did": "Gi4hghe8LzKCfHRFnSauL1",
        "did_doc~attach": {
            "@id": "90adc843-c534-4737-90de-a5d9e44415c0",
            "mime-type": "application/json",
            "data": {
                "base64": "eyJAY29u...wMzAifV19",
                "jws": {
                    "header": {
                        "kid": "did:key:z6MknxLkXkkhibAJw6ULnTaPkZpFLFNpRUYBa3NkR3kWYrVy"
                    },
                    "protected": "eyJhbGciO...clZ5In19",
                    "signature": "QFuAY4YxaFqrjMYmeTiplARXDCu1JRwRXsPYXA_X_AFNs-vLLj7vf9MwUqezQAg5zYQGv4QJW9Q6jOxDaRycBA"
                }
            }
        }
    }
)
```

Again, and perhaps more interestingly, we could also do this using DIDComm V2 preview protocols

```shell
Alice>> rfc0434 create-invitation --inviter acme --dcv2
Acme created an RFC0434 Invitation: [key=D6LVaw3C2Y5xFVrePCerZBFWvSx6HWMuzhAqMWUqw4x2, url=http://192.168.0.10:8130]

Alice>> rfc0434 receive-invitation --dcv2 
Alice received an RFC0434 Invitation: [key=D6LVaw3C2Y5xFVrePCerZBFWvSx6HWMuzhAqMWUqw4x2, url=http://192.168.0.10:8130]
                                                                                                                                                                                                                     Invi:D6LVaw3
Alice>> rfc0048 send-ping --dcv2
Alice received a Trust Ping response
                                                                                                                                                                                                                     Conn:a898df7
Alice>> wallet messages 
Messages:
[id=8180da5f-043c-4d2c-b46a-425ea8b78af3, thid=8180da5f-043c-4d2c-b46a-425ea8b78af3, type=https://didcomm.org/out-of-band/2.0-preview/invitation]
[id=fc292f99-eb72-4443-a4e4-bb6f2f658f65, thid=fc292f99-eb72-4443-a4e4-bb6f2f658f65, type=https://didcomm.org/trust_ping/2.0-preview/ping]
[id=67f18d32-dcbe-4459-a534-63af9e1cce5e, thid=fc292f99-eb72-4443-a4e4-bb6f2f658f65, type=https://didcomm.org/trust_ping/2.0-preview/ping_response]

Alice>> wallet messages --msg=fc292f99 -v
EndpointMessage(
    headers={
        MessageId=fc292f99-eb72-4443-a4e4-bb6f2f658f65,
        MessageMediaType=application/didcomm-plain+json,
        MessageType=https://didcomm.org/trust_ping/2.0-preview/ping
    },
    body={
        "id":"fc292f99-eb72-4443-a4e4-bb6f2f658f65",
        "typ":"application/didcomm-plain+json",
        "type":"https://didcomm.org/trust_ping/2.0-preview/ping",
        "from":"did:key:z6MkqDaHchxszHLyhyAFG4guQdPmxv6jZpV1hH27JKCqBaZm",
        "to":[
            "did:key:z6MkwAxfM32RTU5CJgFFgE38gznHSxjYZGsPuJ7xvGTzCmbQ"
        ],
        "created_time":1676366926,
        "expires_time":1676453326,
        "body":{
            "comment":"Ping from Alice"
        },
        "attachments":[
            {
                "id":"4836047a-8ba4-4cab-a2d4-3e6af2e48859",
                "data":{
                    "jws":null,
                    "hash":null,
                    "json":{
                        "did":"did:key:z6MkqDaHchxszHLyhyAFG4guQdPmxv6jZpV1hH27JKCqBaZm",
                        "keyAgreements":[
                            "did:key:z6MkqDaHchxszHLyhyAFG4guQdPmxv6jZpV1hH27JKCqBaZm#key-x25519-1"
                        ],
                        "authentications":[
                            "did:key:z6MkqDaHchxszHLyhyAFG4guQdPmxv6jZpV1hH27JKCqBaZm#key-1"
                        ],
                        "verificationMethods":[
                            {
                                "id":"did:key:z6MkqDaHchxszHLyhyAFG4guQdPmxv6jZpV1hH27JKCqBaZm#key-1",
                                "type":"JSON_WEB_KEY_2020",
                                "verificationMaterial":{
                                    "format":"JWK",
                                    "value":"{
                                        \"kty\":\"OKP\",
                                        \"crv\":\"Ed25519\",
                                        \"x\":\"n-8NCt6DcUrb2JZJBcGyjRVRP4AHH63u8zXMA7j5QoA\"
                                    }"
                                },
                                "controller":"did:key:z6MkqDaHchxszHLyhyAFG4guQdPmxv6jZpV1hH27JKCqBaZm#key-1"
                            },
                            {
                                "id":"did:key:z6MkqDaHchxszHLyhyAFG4guQdPmxv6jZpV1hH27JKCqBaZm#key-x25519-1",
                                "type":"JSON_WEB_KEY_2020",
                                "verificationMaterial":{
                                    "format":"JWK",
                                    "value":"{
                                        \"kty\":\"OKP\",
                                        \"crv\":\"X25519\",
                                        \"x\":\"qwmMMf08jZbpbV-jzAeepr7VLxoaUHN5TDZp0p13K28\"
                                    }"
                                },
                                "controller":"did:key:z6MkqDaHchxszHLyhyAFG4guQdPmxv6jZpV1hH27JKCqBaZm#key-x25519-1"
                            }
                        ],
                        "didCommServices":[
                            {
                                "id":"did:key:z6MkqDaHchxszHLyhyAFG4guQdPmxv6jZpV1hH27JKCqBaZm#didcomm-1",
                                "serviceEndpoint":"http://192.168.0.10:8130",
                                "accept":[
                                    "didcomm/v2"
                                ]
                            }
                        ]
                    }
                },
                "media_type":"application/did+json"
            }
        ]
    }
)
```

Here we see how the Invitee (Alice) communicates her DID Document as an attachment to a DIDComm V2 message. 
As the message type suggests, this again isn't official protocol content - for details see 
[Nessus DidComm RFC0048: Trust Ping 2.0](https://github.com/tdiesler/nessus-didcomm/tree/main/features/0048-trust-ping)

#### RFC0434 Connect Shortcut

Because Out-of-Band Invitation followed by some sort of Did exchange is so common and the foundation for almost every other protocol, there
is a shortcut available directly on the RFC0434 protocol

```shell
Alice>> rfc0434 connect faber alice
Faber created an RFC0434 Invitation: [key=3PViHhFjUMnEuLeucNaPxdoGFoq5XoyetWBhX1KH3nvt, url=http://192.168.0.10:8030]
Alice received an RFC0434 Invitation: [key=3PViHhFjUMnEuLeucNaPxdoGFoq5XoyetWBhX1KH3nvt, url=http://192.168.0.10:8030]
Alice-Faber [id=eaa366b7-233c-4f49-96b0-07b8a2d79f33, myDid=did:sov:KKfaxF828Butw7YhxrCwLg, theirDid=did:sov:SQER4xEDgZZ96SSuh8AoTq, state=ACTIVE]
```

or 

```shell
Alice>> rfc0434 connect acme alice --dcv2
Acme created an RFC0434 Invitation: [key=EM3w7YdDCwzBLwKja3RToeeKvNpuRwnt74HLumG6RxQ5, url=http://192.168.0.10:8130]
Alice received an RFC0434 Invitation: [key=EM3w7YdDCwzBLwKja3RToeeKvNpuRwnt74HLumG6RxQ5, url=http://192.168.0.10:8130]
Alice-Acme [id=b302c1c3-a3e3-4cb7-993d-274599951c3f, myDid=did:sov:YH32aNN2QA2bJN7kUupxk5, theirDid=did:sov:RYrHMthsk5nFPF7QDFhBBa, state=ACTIVE]
```

Alice should now have multiple connections

```shell
Alice>> wallet connection 
Wallet connections:
Alice-Acme [id=08c4a2ec-2f91-4b6e-82af-4e71f70be411, myDid=did:key:z6Mkh31vmcP83Hs5XJeaFR15vjdGB95bkhKs2YnrkiLmQe5Q, theirDid=did:key:z6MkqmwGzCNiQmzyn5N13aBwDJivatXQfs9Pp2WkBbntw9EN, state=ACTIVE]
Alice-Faber [id=7c67f6e5-805e-41ae-b78d-d03f66efd257, myDid=did:sov:L8shpteP48VeEGn5XDyQoF, theirDid=did:sov:6c7cKA8aojYTBx39z2i9mM, state=ACTIVE]
```

and multiple DIDs

```shell
Alice>> wallet did -v
Wallet dids:
Did(
    id=z6Mkh31vmcP83Hs5XJeaFR15vjdGB95bkhKs2YnrkiLmQe5Q,
    method=KEY,
    algorithm=EdDSA_Ed25519,
    verkey=3aktBN8ghkNcQoosZr3F5e5GMZokLp5WLXsvvSNkVRJ2
)
Did(
    id=L8shpteP48VeEGn5XDyQoF,
    method=SOV,
    algorithm=EdDSA_Ed25519,
    verkey=BRvK5GDiL1rNkcCxkjqp5JkxfkGwFZ2XAucUGM54g4M1
)
```

Notice, how she uses DID method `sov` with Faber and `key` with Acme

### RFC0048: Trust Ping

Trust Ping is an integral of establishing a peer connection - we've seen it above already. 
It is however also available as a separate protocol/command.

Lets see, what it looks like in DIDComm V2 ...

```shell
Alice>> rfc0048 send-ping --dcv2
Alice received a Trust Ping response
                                                                                                                                                                                                                     Conn:0b8d154
Alice>> rfc0048 send-ping --dcv2 -v
Alice received a Trust Ping response
EndpointMessage(
    headers={
        MessageId=3a6b78e0-3768-4c9c-9616-5f3805d25ea4,
        MessageMediaType=application/didcomm-plain+json,
        MessageType=https://didcomm.org/trust_ping/2.0-preview/ping
    },
    body={
        "id":"3a6b78e0-3768-4c9c-9616-5f3805d25ea4",
        "typ":"application/didcomm-plain+json",
        "type":"https://didcomm.org/trust_ping/2.0-preview/ping",
        "from":"did:key:z6Mkm8ezEDdR1Au4TxyW7UQejVduZsbhdGcc6pC7oNMKxhxs",
        "to":[
            "did:key:z6Mkit4ysNAR9YmUCnyti1Sp2yGF2AJEbwV92j2Ny5Yduwcp"
        ],
        "created_time":1676292282,
        "expires_time":1676378682,
        "body":{
            "comment":"Ping from Alice"
        }
    }
)
EndpointMessage(
    headers={
        MessageId=25ab0958-0764-4fe9-8f6b-b9f857c60bd5,
        MessageMediaType=application/didcomm-plain+json,
        MessageProtocolUri=https://didcomm.org/trust_ping/2.0-preview,
        MessageRecipientVerkey=7gPwdyNyfdQbMU8oRuSotQ5ukJKrDPNFQoHBy6PK3VBV,
        MessageSenderVerkey=5RowH7uyp1H16J9C2SUyBsiFCb2PC4EnLi7T8oacziqS,
        MessageThid=3a6b78e0-3768-4c9c-9616-5f3805d25ea4,
        MessageType=https://didcomm.org/trust_ping/2.0-preview/ping_response
    },
    body={
        "id":"25ab0958-0764-4fe9-8f6b-b9f857c60bd5",
        "typ":"application/didcomm-plain+json",
        "type":"https://didcomm.org/trust_ping/2.0-preview/ping_response",
        "from":"did:key:z6Mkit4ysNAR9YmUCnyti1Sp2yGF2AJEbwV92j2Ny5Yduwcp",
        "to":[
            "did:key:z6Mkm8ezEDdR1Au4TxyW7UQejVduZsbhdGcc6pC7oNMKxhxs"
        ],
        "created_time":1676292282,
        "expires_time":1676378682,
        "body":{
            "comment":"Pong from Acme"
        },
        "thid":"3a6b78e0-3768-4c9c-9616-5f3805d25ea4"
    }
)
```

Note, on the wire these messages will be signed+encrypted and not plain text.
In the first Trust Ping, the Invitee may attach his/her peer Did Document   

Currently, the DIDComm V2 [MessageBuilder](https://github.com/sicpa-dlab/didcomm-jvm/blob/main/lib/src/main/kotlin/org/didcommx/didcomm/message/Message.kt#L139)
API does not provide write access to this field ... not sure if this is intentional

### RFC0095: Basic Message

With DIDComm V2, we have the choice of sending a message

1. [Plaintext](https://identity.foundation/didcomm-messaging/spec/#didcomm-plaintext-messages)
2. [Signed](https://identity.foundation/didcomm-messaging/spec/#didcomm-signed-messages)
3. [Encrypted](https://identity.foundation/didcomm-messaging/spec/#didcomm-encrypted-messages)

The Nessus [RFC0095 Basic Message 2.0](https://github.com/tdiesler/nessus-didcomm/tree/main/features/0095-basic-message) 
preview also supports these variants.

```shell
Alice>> rfc0095 send 'Your hovercraft is full of eels' --dcv2 -v
Alice sent: Your hovercraft is full of eels
EndpointMessage(
    headers={
        MessageId=13fa75fb-c6cf-4a8b-a549-2207cd31ddcb,
        MessageMediaType=application/didcomm-plain+json,
        MessageType=https://didcomm.org/basicmessage/2.0-preview/message
    },
    body={
        "id":"13fa75fb-c6cf-4a8b-a549-2207cd31ddcb",
        "typ":"application/didcomm-plain+json",
        "type":"https://didcomm.org/basicmessage/2.0-preview/message",
        "from":"did:key:z6MkorRGtXqsPnD3bwqT6wGbNJDCEeD9zY1DfbnEPkkzFLDz",
        "to":[
            "did:key:z6MksVz8urciusNUhE8SS2BxT3S6fUHJVwbcja6fMb9qBNZX"
        ],
        "created_time":1676295686,
        "body":{
            "content":"Your hovercraft is full of eels"
        }
    }
)
```

The default for DIDComm V2 basic messages is Plaintext, but we could also add the `--sign` or `--encrypt` options.
Nessus generally only records unpacked messages, so that signed/encrypted messages would not look different than the one above.

In the logfile however, a signed message would look like this ...

```log
{
  "payload": "eyJpZCI6IjQ3NGFlMmVjLTIyNTEtNDEwNS04NzRmLThhMjY1NTU2NDQ2MCIsInR5cCI6ImFwcGxpY2F0aW9uL2RpZGNvbW0tcGxhaW4ran...",
  "signatures": [
    {
      "protected": "eyJ0eXAiOiJhcHBsaWNhdGlvbi9kaWRjb21tLXNpZ25lZCtqc29uIiwiYWxnIjoiRWREU0EifQ",
      "signature": "T0FZRSIdm--HoabFr3avCpXtY3wHkRsiOUOyZKN9jgf7yVIb-g54CQma-W9olfHmECpAAejt_TJVuYlXKp_nAw",
      "header": {
        "kid": "did:key:z6MkfR1WXHAArbqDAZQgHM4Fem8Gp6HJntWAdkg8VCHf8y13#key-1"
      }
    }
  ]
}
```

and an encrypted message like this ...

```log
{
  "ciphertext": "RB8mWAupqO8KOyz7_ZbE2_zfXR_0YlJcfXHySeZE3pcnl2ANLCiwwHCGZt-MryhzAEaiykt8OcAoPPAxjP2hWU28MJ7QTVCiTuztRVH...",
  "protected": "eyJlcGsiOnsia3R5IjoiT0tQIiwiY3J2IjoiWDI1NTE5IiwieCI6InIycTFKNGtRY2RVNkFzRUF0THNibWdyMFplWlY2dXpubENvRmJr...",
  "recipients": [
    {
      "encrypted_key": "Et8R0xXqC_m16QBCiHX5QU7A-1Ii_GPOquC5PpHqKOxIoJa30SrrbM1CPbeKIZ8OdyEA0EefYSESsoFVHZ_thbMHWIVJIE6a",
      "header": {
        "kid": "did:key:z6MkvDt2yFvNrK4nsQZjZxHRuMfLRBL5zBGLVQ7r8iXVgCEX#key-x25519-1"
      }
    }
  ],
  "tag": "huXKZU7eRRr1oPxPKViRXhr5sbh4nqXgdVaRiKMhaBM",
  "iv": "QJVi1zZw46mEEapwyclr_A"
}
```

### Wrapping up

That's it for now - thanks for reading and perhaps even trying this out for yourself.

Here are some ideas on how to move on from here

* Ideally, I'd like to work with some other agent on true interoperability
* Nessus preview protocols need to get replaced by actual DIDComm protocols 
* Verifiable credentials and perhaps revocation of which needs to get added
* Support for other DID methods e.g. peer, ebsi, etc
* Support for an actual DID Document Resolver
* Persistent/Secure key storage
* Stuff from your wish list? 

As always, please feel free to comment on code and file issues.

Enjoy
