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
Version: 23.3.0

>> help
  System:
    exit       exit from app/script
    help       command help
  Commands:
    agent      Agent related commands
    clear      Clear the terminal screen
    commands   Show tree of available commands
    connection Connection related commands
    did        Did related commands
    invitation Invitation related commands
    message    Message related commands
    rfc0048    RFC0048 Trust Ping
    rfc0095    RFC0095 Basic Message
    rfc0434    RFC0434 Out-of-Band Invitation
    vc         Verifiable credential commands
    wallet     Multitenant wallet commands
```

Help shows a number of top-level commands. 

### Work with multitenant wallets  

On startup, the CLI examines the current environment and loads the state of already existing wallets it can find

Here we have one AcaPy wallet that is currently online 

```shell
>> wallet list
Government [agent=AcaPy, url=http://192.168.0.10:8031]

>> wallet list --verbose
{
  "authToken": "eyJ0eXA...14w4",
  "id": "3f3d74f4-8f45-49a5-82ee-6117c49a05d9",
  "name": "Government",
  "agentType": "AcaPy",
  "storageType": "INDY",
  "endpointUrl": "http://192.168.0.10:8031"
}
```

#### Creating wallets for Faber and Alice

A wallet is associated with one of many supported agent types - above, we see an AcaPy wallet. 
Let's now create a native Nessus wallet for Alice

```shell
>> wallet create --name Faber --agent=AcaPy
Wallet created: Faber [agent=AcaPy, type=IN_MEMORY, url=http://192.168.0.10:8030]

Faber>> wallet create --name Alice
Wallet created: Alice [agent=Nessus, type=IN_MEMORY, url=http://192.168.0.10:9000]

Alice>>
```

The prompt changes to indicate that the current context wallet.

In case we want to issue multiple commands in the context of another wallet, we can `switch` to it.
Alternatively, we can stay with the current context wallet and explicitly name the wallet for a given command.

```shell
>> wallet switch fab

Faber>>
```

The CLI supports command/option completion with TAB and command history with UP/DOWN.
An element selection (in this case an alias for a wallet) can be abbreviated and case-insensitive.

### Agent Endpoints

Every wallet has a public HTTP endpoint - multiple wallets may share the same endpoint.

For Nessus wallets, the CLI can start/stop these endpoints individually. This is useful, when 
we want to simulate an agent becoming unreachable. Also, wallets may want to use different processes.

Lets now start Alice's HTTP endpoint

```shell
Alice>> agent start
Started Camel endpoint on 192.168.0.10:9000
```

This starts an [Apache Camel](https://camel.apache.org) endpoint, and hence provides a plethora of routing 
transformation and other processing possibilities for incoming DIDComm messages. 

### RFC0434: Out-of-Band Invitation

The CLI can support many protocols in multiple versions. This is useful for scripting various interoperability scenarios.

Let's start with the classic case of Faber College inviting Alice to a peer connection.
We can then use this connection to then exchange messages from higher level protocols. 

#### Faber creates an RFC0434 Out-of-Band Invitation V1

```shell
Alice>> rfc0434 create-invitation --inviter faber
Faber created an RFC0434 Invitation: did:key:z6MkojRLEgdnFTshDA9d6ZddWF53B2MqhczMJAe1izV2ZdxF [key=AHAHeSPLuvPE6fJvQzfnf9X3MT5zHjjzc9j5tiX1eRAs, url=http://192.168.0.10:8030]

Alice>> rfc0434 receive-invitation 
Alice received an RFC0434 Invitation: did:key:z6MkojRLEgdnFTshDA9d6ZddWF53B2MqhczMJAe1izV2ZdxF [key=AHAHeSPLuvPE6fJvQzfnf9X3MT5zHjjzc9j5tiX1eRAs, url=http://192.168.0.10:8030]
Alice-Faber [id=355e157b-fcf1-4c7b-825e-0573881b422a, myDid=did:sov:Aozdv2kvCHQzuptTCKxmfT, theirDid=did:sov:A1q4LmpT4HfuBcLn3NmqRE, state=ACTIVE]
```

Internally, this uses an implementation of the [RFC0023 DID Exchange](https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange) protocol, like this ...

```kotlin
    /**
     * Inviter (Faber) creates an Out-of-Band Invitation
     * Invitee (Alice) receives and accepts the Invitation
     * Requester (Alice) send the DidEx Request
     * Responder (Faber) accepts the DidEx Request and sends a Response
     * Requester (Alice) sends the DidEx Complete message
     * Requester (Alice) sends a Trust Ping
     * Responder (Faber) sends a Trust Ping Response
     */

    val mex = MessageExchange()
        .withProtocol(RFC0434_OUT_OF_BAND_V1)
        .createOutOfBandInvitation(faber, "Faber invites Alice")
        .receiveOutOfBandInvitation(alice)

        .withProtocol(RFC0023_DIDEXCHANGE_V1)
        .sendDidExchangeRequest(alice)
        .awaitDidExchangeResponse()
        .sendDidExchangeComplete()

        .withProtocol(RFC0048_TRUST_PING_V1)
        .sendTrustPing()
        .awaitTrustPingResponse()

        .getMessageExchange()
```

Alice has now an active connection with Faber. On the right we see the current context connection. 
It works similar to the context wallet, and it used when not given explicitly. 

Let's do this again with more geeky options ...

```shell
Alice>> rfc0434 create-invitation --inviter faber --verbose
Faber created an RFC0434 Invitation: 
{
  "@id": "2105f530-8d33-44fc-8e82-b5f6ea0c1cc4",
  "@type": "https://didcomm.org/out-of-band/1.1/invitation",
  "label": "Invitation from Faber",
  "accept": [
    "didcomm/v2"
  ],
  "handshake_protocols": [
    "https://didcomm.org/didexchange/1.0"
  ],
  "services": [
    {
      "id": "#inline",
      "type": "did-communication",
      "recipientKeys": [
        "did:key:z6Mki6XeBToversGta6UXZR69MfKg5AGNt6DxBAZ4T6SB2vP"
      ],
      "serviceEndpoint": "http://192.168.0.10:8030"
    }
  ],
  "state": "initial"
}
```

Even more interesting, Faber could invite Alice using DIDComm V2
For this we need to switch Faber to an agent that supports DCV2, Nessus for example ;-) 

#### Faber creates an RFC0434 Out-of-Band Invitation V2

```shell
Alice>> wallet remove faber                                                                                                                                                                                         [Conn:355e157]
Wallet removed: Faber [agent=AcaPy, type=IN_MEMORY, url=http://192.168.0.10:8030]

Alice>> wallet create --name Faber
Wallet created: Faber [agent=Nessus, type=IN_MEMORY, url=http://192.168.0.10:9000]

Alice>> rfc0434 create-invitation --inviter=Faber --verbose --dcv2
Faber created an RFC0434 Invitation
{
  "id": "8d813c29-033b-445c-bb5a-1e452c5e922b",
  "type": "https://didcomm.org/out-of-band/2.0-preview/invitation",
  "from": "did:key:z6MkuGdJtRD79LEHk5LJ4gjZdZY5FH5h1CoTQB4yky3kFZam",
  "accept": [
    "didcomm/v2"
  ],
  "attachments": [
    {
      "id": "f13fdfe2-3160-414d-9173-22d5e7d2a5aa",
      "data": {
        "json": {
          "id": "did:key:z6MkuGdJtRD79LEHk5LJ4gjZdZY5FH5h1CoTQB4yky3kFZam",
          "authentication": [
            "did:key:z6MkuGdJtRD79LEHk5LJ4gjZdZY5FH5h1CoTQB4yky3kFZam#z6MkuGdJtRD79LEHk5LJ4gjZdZY5FH5h1CoTQB4yky3kFZam"
          ],
          "keyAgreement": [
            "did:key:z6MkuGdJtRD79LEHk5LJ4gjZdZY5FH5h1CoTQB4yky3kFZam#z6LSnzFWskr9bshHkD6VFMFDk7vpRVu8WbqnggphMY8LzLKX"
          ],
          "verificationMethod": [
            {
              "id": "did:key:z6MkuGdJtRD79LEHk5LJ4gjZdZY5FH5h1CoTQB4yky3kFZam#z6MkuGdJtRD79LEHk5LJ4gjZdZY5FH5h1CoTQB4yky3kFZam",
              "type": "Ed25519VerificationKey2018",
              "controller": "did:key:z6MkuGdJtRD79LEHk5LJ4gjZdZY5FH5h1CoTQB4yky3kFZam",
              "publicKeyBase58": "FpNGJAxfonjpdaVbP7minTz5RhoqbKZ6iAA3vh5jLLoP"
            },
            {
              "id": "did:key:z6MkuGdJtRD79LEHk5LJ4gjZdZY5FH5h1CoTQB4yky3kFZam#z6LSnzFWskr9bshHkD6VFMFDk7vpRVu8WbqnggphMY8LzLKX",
              "type": "X25519KeyAgreementKey2019",
              "controller": "did:key:z6MkuGdJtRD79LEHk5LJ4gjZdZY5FH5h1CoTQB4yky3kFZam",
              "publicKeyBase58": "CK5MMT3HWQyYepiiihjGRXiLaMN1ozfdoi71s5UpGxYm"
            }
          ],
          "service": [
            {
              "id": "did:key:z6MkuGdJtRD79LEHk5LJ4gjZdZY5FH5h1CoTQB4yky3kFZam#didcomm-1",
              "type": "DIDCommMessaging",
              "accept": [
                "didcomm/v2"
              ],
              "serviceEndpoint": "http://192.168.0.10:9000"
            }
          ]
        }
      },
      "mediaType": "application/did+json"
    }
  ]
}
```

The message above follows the general layout for [DIDComm V2 Out-of-Band](https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages) messages.
However, the spec (unfortunately or purposefully) leaves out the specifics of a DIDComm peer-to-peer Invitation.

In such cases, Nessus makes a number of assumptions for this [POC](https://github.com/tdiesler/nessus-didcomm/blob/main/docs/proof-of-concept.md) implementation.
These Nessus preview protocols are documented [here](https://github.com/tdiesler/nessus-didcomm/tree/main/features).

Generally, everything we demonstrate with Faber-Alice (i.e. AcaPy/Nessus) also works in it's DIDComm V2 variant.
In the future, when DIDComm V2 becomes available in AcaPy, we expect message content and type to change to reflect the respective DCV2 standards.

For now, a [Nessus RFC0434 Invitation][rfc0434v2] message has a Did Document attached that the Invitee can use to establish a peer connection with the Inviter.
This could also have been done in a number of other ways ...

* [did:peer method 1](https://identity.foundation/peer-did-method-spec/#generation-method)
* [did:keri](https://identity.foundation/keri/did_methods/)

We expect the upcoming [Aries Interop Profile 3](https://hackmd.io/_Kkl9ClTRBu8W4UmZVGdUQ) to nail down such details. 

#### Alice receives an RFC0434 Out-of-Band Invitation V2

When Alice received the Invitation from Faber, she can establish the connection by sending her connection details. 

```shell
Alice>> rfc0434 receive-invitation
Alice received an RFC0434 Invitation: did:key:z6MkuGdJtRD79LEHk5LJ4gjZdZY5FH5h1CoTQB4yky3kFZam [key=FpNGJAxfonjpdaVbP7minTz5RhoqbKZ6iAA3vh5jLLoP, url=http://192.168.0.10:9000]
Alice-Faber [id=3da3baa8-aac6-4ec2-a472-29f5c5435f7f, myDid=did:key:z6Mkpzrq3Pf6xPkBxppPCh7XE1NpfPTYqGbkodMdWcVaaMFQ, theirDid=did:key:z6MkngmjqN8hVSBwvz5KVEMSwhiLjqgP7VWNgMpVjegRJiMr, state=ACTIVE]
```

Again, the connection is now established, and we can look at it like this ...

```shell
Alice>> connection show -v                                                                                                                                                                                          [Conn:f4d04fe]
{
  "id": "3da3baa8-aac6-4ec2-a472-29f5c5435f7f",
  "agent": "Nessus",
  "invitationKey": "FpNGJAxfonjpdaVbP7minTz5RhoqbKZ6iAA3vh5jLLoP",
  "myRole": "INVITEE",
  "myLabel": "Invitee Alice on NESSUS",
  "myEndpointUrl": "http://192.168.0.10:9000",
  "theirRole": "INVITER",
  "theirEndpointUrl": "http://192.168.0.10:9000",
  "state": "ACTIVE",
  "myDid": {
    "method": "KEY",
    "algorithm": "EdDSA_Ed25519",
    "verkey": "BYbnT9QfcrFirKygX89gNuppqpBhRPMQ7cShgLXZf8U2",
    "id": "z6Mkpzrq3Pf6xPkBxppPCh7XE1NpfPTYqGbkodMdWcVaaMFQ"
  },
  "theirDid": {
    "method": "KEY",
    "algorithm": "EdDSA_Ed25519",
    "verkey": "9EWhF7tG9thUpVEcofPc6cALvGQXhcG1zLuZuNiQPVaU",
    "id": "z6MkngmjqN8hVSBwvz5KVEMSwhiLjqgP7VWNgMpVjegRJiMr"
  }
}
```

Nessus records the messages that are being exchanged for each connection.

```shell
Alice>> message list 
[id=8d813c29-033b-445c-bb5a-1e452c5e922b, thid=8d813c29-033b-445c-bb5a-1e452c5e922b, type=https://didcomm.org/out-of-band/2.0-preview/invitation]
[id=5779aec8-deaa-4ac6-905c-fdc22f6a6f75, thid=5779aec8-deaa-4ac6-905c-fdc22f6a6f75, type=https://didcomm.org/trust_ping/2.0-preview/ping]
[id=7de47310-0ca5-4e1b-a2da-c1c864576c18, thid=5779aec8-deaa-4ac6-905c-fdc22f6a6f75, type=https://didcomm.org/trust_ping/2.0-preview/ping_response]
```

For example, Alice's ping request would look like this ...

```shell
Alice>> message show 5779aec8 -v                                                                                                                                                                            [Conn:f4d04fe]
EndpointMessage(
    headers={
        MessageId=5779aec8-deaa-4ac6-905c-fdc22f6a6f75,
        MessageMediaType=application/didcomm-plain+json,
        MessageType=https://didcomm.org/trust_ping/2.0-preview/ping
    },
    body={
        "id":"5779aec8-deaa-4ac6-905c-fdc22f6a6f75",
        "typ":"application/didcomm-plain+json",
        "type":"https://didcomm.org/trust_ping/2.0-preview/ping",
        "from":"did:key:z6Mkpzrq3Pf6xPkBxppPCh7XE1NpfPTYqGbkodMdWcVaaMFQ",
        "to":[
            "did:key:z6MkuGdJtRD79LEHk5LJ4gjZdZY5FH5h1CoTQB4yky3kFZam"
        ],
        "created_time":1676896602,
        "expires_time":1676983002,
        "body":{
            "comment":"Ping from Alice"
        },
        "attachments":[
            {
                "id":"71de6122-1073-4e74-9d72-d7511a263b1a",
                "data":{
                    "jws":null,
                    "hash":null,
                    "json":{
                        "id":"did:key:z6Mkpzrq3Pf6xPkBxppPCh7XE1NpfPTYqGbkodMdWcVaaMFQ",
                        "authentication":[
                            "did:key:z6Mkpzrq3Pf6xPkBxppPCh7XE1NpfPTYqGbkodMdWcVaaMFQ#z6Mkpzrq3Pf6xPkBxppPCh7XE1NpfPTYqGbkodMdWcVaaMFQ"
                        ],
                        "keyAgreement":[
                            "did:key:z6Mkpzrq3Pf6xPkBxppPCh7XE1NpfPTYqGbkodMdWcVaaMFQ#z6LSnVHyJWmBcJ9NG28nRWw44vm3KJxcUeYhHWk4m2RH5FFk"
                        ],
                        "verificationMethod":[
                            {
                                "id":"did:key:z6Mkpzrq3Pf6xPkBxppPCh7XE1NpfPTYqGbkodMdWcVaaMFQ#z6Mkpzrq3Pf6xPkBxppPCh7XE1NpfPTYqGbkodMdWcVaaMFQ",
                                "type":"Ed25519VerificationKey2018",
                                "controller":"did:key:z6Mkpzrq3Pf6xPkBxppPCh7XE1NpfPTYqGbkodMdWcVaaMFQ",
                                "publicKeyBase58":"BYbnT9QfcrFirKygX89gNuppqpBhRPMQ7cShgLXZf8U2"
                            },
                            {
                                "id":"did:key:z6Mkpzrq3Pf6xPkBxppPCh7XE1NpfPTYqGbkodMdWcVaaMFQ#z6LSnVHyJWmBcJ9NG28nRWw44vm3KJxcUeYhHWk4m2RH5FFk",
                                "type":"X25519KeyAgreementKey2019",
                                "controller":"did:key:z6Mkpzrq3Pf6xPkBxppPCh7XE1NpfPTYqGbkodMdWcVaaMFQ",
                                "publicKeyBase58":"Bp7onCxKWqRdAdm1tsR6kLYZUARVn3NYQY2PGZmkMsUz"
                            }
                        ],
                        "service":[
                            {
                                "id":"did:key:z6Mkpzrq3Pf6xPkBxppPCh7XE1NpfPTYqGbkodMdWcVaaMFQ#didcomm-1",
                                "type":"DIDCommMessaging",
                                "accept":[
                                    "didcomm/v2"
                                ],
                                "serviceEndpoint":"http://192.168.0.10:9000"
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

Here we see how the Invitee (Alice) communicates her DID Document as an attachment to a DIDComm V2 Trust Ping. 
As the message type suggests, this again isn't official protocol content - for details see 
[Nessus RFC0048: Trust Ping 2.0][rfc0048v2]

Faber can now use the `fromPrior` message header that is built into DIDComm V2, to rotate the DID that it wants to use for this peer connection.
This is another proprietary feature of [Nessus RFC0048: Trust Ping 2.0][rfc0048v2] 


#### Nessus RFC0434 Connect Shortcut

Because Out-of-Band Invitation followed by some sort of Did exchange is so common and the foundation for almost every other protocol, there
is a shortcut available directly on the RFC0434 protocol

```shell
Alice>> rfc0434 connect --dcv2 faber alice                                                                                                                                                                          [Conn:9939eec]
Faber created an RFC0434 Invitation: did:key:z6MkvAmFiRcVxaUo4MTN9DJfmcY1jgbqaorAc5ZLDNrF791Y [key=GiWD8BN4d2zKwrcfTeLpvWz1v7KzAvbov4eQP6tEBvEA, url=http://192.168.0.10:9000]
Alice received an RFC0434 Invitation: did:key:z6MkvAmFiRcVxaUo4MTN9DJfmcY1jgbqaorAc5ZLDNrF791Y [key=GiWD8BN4d2zKwrcfTeLpvWz1v7KzAvbov4eQP6tEBvEA, url=http://192.168.0.10:9000]
Alice-Faber [id=20e82029-ef64-4572-a6d2-7ac661435d32, myDid=did:key:z6MkvSHUgybJtTCGemvJgUvURZPGVFkZgfUKSam6Z7QcP3EX, theirDid=did:key:z6MkvMJwBXeykWgsCxkoJdJUVdSztFZMztt2qH3JCWK5NfwC, state=ACTIVE]
```

Alice should now have multiple connections

```shell
Alice>> connection list                                                                                                                                                                                             [Conn:20e8202
Alice-Faber [id=f4d04fe3-4ec6-4d96-aa1b-ac05b4dc0567, myDid=did:key:z6MkrULdVeMohPjsvuJNXacVNKNNp2ovhdKnj69xTf4o8ziq, theirDid=did:key:z6MkouBRMBzQVef8c7dPCn4ueh8CZo5AiKJC8HDzs9bYvrgA, state=ACTIVE]
Alice-Faber [id=20e82029-ef64-4572-a6d2-7ac661435d32, myDid=did:key:z6MkvSHUgybJtTCGemvJgUvURZPGVFkZgfUKSam6Z7QcP3EX, theirDid=did:key:z6MkvMJwBXeykWgsCxkoJdJUVdSztFZMztt2qH3JCWK5NfwC, state=ACTIVE]
```

and multiple DIDs

```shell
Alice>> did list                                                                                                                                                                                                    [Conn:20e8202]
did:key:z6MkrULdVeMohPjsvuJNXacVNKNNp2ovhdKnj69xTf4o8ziq [algorithm=EdDSA_Ed25519, verkey=D25auQ7NMrFQpQTfr1eeXDpNzTY5Hk5S35F2dP6nDmwT]
did:key:z6MkvSHUgybJtTCGemvJgUvURZPGVFkZgfUKSam6Z7QcP3EX [algorithm=EdDSA_Ed25519, verkey=Gz2S6jLsYuhoYH5bzuxdaTqGfgUiGnDxkZrAiqSbTpT9]
```

### RFC0048: Trust Ping

Trust Ping is an integral part of establishing a peer connection - we've seen it above already. 
It is however also available as a separate protocol/command.

Let's see, what it looks like in DIDComm V2 ...

```shell
Alice>> rfc0048 send-ping --dcv2
Alice received a Trust Ping response
                                                                                                                                                                                                                     Conn:0b8d154
Alice>> rfc0048 send-ping --dcv2 -v
Alice received a Trust Ping response
EndpointMessage(
    headers={
        MessageId=85365fc0-7124-4ab9-aca5-2a711313f522,
        MessageMediaType=application/didcomm-plain+json,
        MessageType=https://didcomm.org/trust_ping/2.0-preview/ping
    },
    body={
        "id":"85365fc0-7124-4ab9-aca5-2a711313f522",
        "typ":"application/didcomm-plain+json",
        "type":"https://didcomm.org/trust_ping/2.0-preview/ping",
        "from":"did:key:z6MkvSHUgybJtTCGemvJgUvURZPGVFkZgfUKSam6Z7QcP3EX",
        "to":[
            "did:key:z6MkvMJwBXeykWgsCxkoJdJUVdSztFZMztt2qH3JCWK5NfwC"
        ],
        "created_time":1676877204,
        "expires_time":1676963604,
        "body":{
            "comment":"Ping from Alice"
        }
    }
)
EndpointMessage(
    headers={
        MessageId=5ddd1406-395d-4bda-9824-60bd841d96c2,
        MessageMediaType=application/didcomm-plain+json,
        MessageProtocolUri=https://didcomm.org/trust_ping/2.0-preview,
        MessageRecipientVerkey=Gz2S6jLsYuhoYH5bzuxdaTqGfgUiGnDxkZrAiqSbTpT9,
        MessageSenderVerkey=Gu3tbHQYQyCQ6Tv6d4LdeXu14gHWb1dg9G8NNEM4TT9p,
        MessageThid=85365fc0-7124-4ab9-aca5-2a711313f522,
        MessageType=https://didcomm.org/trust_ping/2.0-preview/ping_response
    },
    body={
        "id":"5ddd1406-395d-4bda-9824-60bd841d96c2",
        "typ":"application/didcomm-plain+json",
        "type":"https://didcomm.org/trust_ping/2.0-preview/ping_response",
        "from":"did:key:z6MkvMJwBXeykWgsCxkoJdJUVdSztFZMztt2qH3JCWK5NfwC",
        "to":[
            "did:key:z6MkvSHUgybJtTCGemvJgUvURZPGVFkZgfUKSam6Z7QcP3EX"
        ],
        "created_time":1676877205,
        "expires_time":1676963605,
        "body":{
            "comment":"Pong from Faber"
        },
        "thid":"85365fc0-7124-4ab9-aca5-2a711313f522"
    }
)
```

Note, on the wire these messages will be signed+encrypted and not plain text.
In the first Trust Ping, the Invitee may attach his/her peer Did Document   

### RFC0095: Basic Message

With DIDComm V2, we have the choice of sending a message

1. [Plaintext](https://identity.foundation/didcomm-messaging/spec/#didcomm-plaintext-messages)
2. [Signed](https://identity.foundation/didcomm-messaging/spec/#didcomm-signed-messages)
3. [Encrypted](https://identity.foundation/didcomm-messaging/spec/#didcomm-encrypted-messages)

The Nessus [RFC0095 Basic Message 2.0][rfc0095v2] preview also supports these variants.

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

[rfc0048v2]: https://github.com/tdiesler/nessus-didcomm/tree/main/features/0048-trust-ping
[rfc0095v2]: https://github.com/tdiesler/nessus-didcomm/tree/main/features/0095-basic-message
[rfc0434v2]: https://github.com/tdiesler/nessus-didcomm/tree/main/features/0434-oob-invitation