## Nessus DIDComm

Nessus DIDComm is about Digital Identity and Verifiable Credentials based on [DIDComm V2](https://identity.foundation/didcomm-messaging/spec/v2.0).

[<img src="docs/img/ssi-book.png" height="200" alt="self sovereign identity">](https://www.manning.com/books/self-sovereign-identity)

The initial scope of this project is laid out in [Proof-of-Concept](./docs/proof-of-concept.md).

### External Documentation

* [The Story of Open SSI Standards](https://www.youtube.com/watch?v=RllH91rcFdE)
* [DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/v2.0)
* [DIDComm JVM](https://github.com/sicpa-dlab/didcomm-jvm)
* [Aries Cloud Agent](https://github.com/hyperledger/aries-cloudagent-python)
* [Aries Protocol RFCs](https://github.com/hyperledger/aries-rfcs/tree/main/features)

### Ledger with VON-Network

This project requires access to a Hyperledger Indy Network. Is recommended to use the [VON Network](https://github.com/bcgov/von-network), developed as a portable Indy Node Network implementation for local development. Instructions for setting up the von-network can be viewed [here](https://github.com/bcgov/von-network#running-the-network-locally).

Basic instructions for using the VON Network are [here](https://github.com/bcgov/von-network/blob/main/docs/UsingVONNetwork.md).

### Start Hyperledger Aries Cloud Agent

Use this when you want to run the tests.

```
docker compose up --detach && docker compose logs -f acapy
```

### Install Siera CLI

[Siera](https://siera.animo.id/) makes self-sovereign identity development easier

```
brew tap animo/siera
brew install animo/agent-cli/siera
```

Now, we can create the default environment

```
siera configuration add -e default -a aca-py -k adminkey -u http://localhost:8031
```

### Onboarding

```
./wallet-bootstrap --create Government --ledger-role TRUSTEE
```

The above should have created the respective siera environment.

### Supported Protocols

| Protocol                                       | AcaPy | Nessus |
|:-----------------------------------------------|:-----:|:------:|
| [RFC0019 Encryption Envelope][rfc0019]         |   x   |   x    |
| [RFC0023 DID Exchange Protocol 1.0][rfc0023]   |   x   |   x    |
| [RFC0048 Trust Ping Protocol 1.0][rfc0048]     |   x   |   x    |
| [RFC0095 Basic Message Protocol 1.0][rfc0095]  |   x   |   x    |
| [RFC0434 Out-of-Band Protocol 1.1][rfc0434]    |   x   |   x    |
| [RFC0048 Trust Ping 2.0][rfc0048v2]            |       |   x    |
| [RFC0095 Basic Message 2.0][rfc0095v2]         |       |   x    |
| [RFC0434 Out-of-Band Protocol 2.0][rfc0434v2]  |       |   x    |

[rfc0019]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0019-encryption-envelope
[rfc0023]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
[rfc0048]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0048-trust-ping
[rfc0095]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0095-basic-message
[rfc0434]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0434-outofband
[rfc0048v2]: features/0048-trust-ping
[rfc0095v2]: features/0095-basic-message
[rfc0434v2]: features/0434-oob-invitation

### CLI Example

Creating a peer connection between Faber (AcaPy) and Alice (Nessus)

```shell
$ didcomm

Nessus DIDComm CLI
Version: 0.23.3

>> wallet list
Government [agent=AcaPy, type=INDY, url=http://192.168.0.10:8031]

>> wallet create --name=Faber --agent=AcaPy
Wallet created: Faber [agent=AcaPy, type=IN_MEMORY, url=http://192.168.0.10:8030]

Faber>> wallet create --name=Alice 
Wallet created: Alice [agent=Nessus, type=IN_MEMORY, url=http://192.168.0.10:8130]

Alice>> agent start
Started Camel endpoint on 192.168.0.10:8130

Alice>> rfc0434 create-invitation --inviter=Faber
Faber created an RFC0434 Invitation: did:key:z6Mkk4KrPgeamSqtMN6UGvQrP2scL9nQmWEUXeEhgiSf8YCd [key=6c4ooSQ9RuMREsFmbMT1XwKcWaWZMcz7qdKmrSUeDKRF, url=http://192.168.0.10:8030]
                                                                                                                                                                                                      Invi:6c4ooSQ
Alice>> rfc0434 receive-invitation 
Alice received an RFC0434 Invitation: did:key:z6Mkk4KrPgeamSqtMN6UGvQrP2scL9nQmWEUXeEhgiSf8YCd [key=6c4ooSQ9RuMREsFmbMT1XwKcWaWZMcz7qdKmrSUeDKRF, url=http://192.168.0.10:8030]
Alice-Faber [id=a95f8a12-86ef-469e-8d2b-afb73b011899, myDid=did:sov:AyXqxQ6abuDojHKsomKMgQ, theirDid=did:sov:CN2tMFmDmd2KeUyQjxeJYU, state=ACTIVE]

Alice>> message list 
[id=72560e3f-abea-492f-b86e-f36976d8e3f7, thid=72560e3f-abea-492f-b86e-f36976d8e3f7, type=https://didcomm.org/out-of-band/1.1/invitation]
[id=3169c72d-7c84-4018-9575-7f2a23ff0bb0, thid=3169c72d-7c84-4018-9575-7f2a23ff0bb0, type=https://didcomm.org/didexchange/1.0/request]
[id=8d931533-28b2-4348-b68f-5626e907b8ca, thid=3169c72d-7c84-4018-9575-7f2a23ff0bb0, type=https://didcomm.org/didexchange/1.0/response]
[id=f70cb005-4efe-45b4-bc3e-c4ba8b39c2fa, thid=3169c72d-7c84-4018-9575-7f2a23ff0bb0, type=https://didcomm.org/didexchange/1.0/complete]
[id=e02e0cd5-63db-4dde-aa73-ace8cb3a0c66, thid=e02e0cd5-63db-4dde-aa73-ace8cb3a0c66, type=https://didcomm.org/trust_ping/1.0/ping]
[id=f7a7be95-e8be-4535-8d47-047ef0e7e9f1, thid=e02e0cd5-63db-4dde-aa73-ace8cb3a0c66, type=https://didcomm.org/trust_ping/1.0/ping_response]
```

### Code Sample

```kotlin
    /** Create the wallets */

    val faber = getWalletByAlias(Faber.name) ?: fail("No Faber")
    
    val alice = Wallet.Builder(Alice.name)
        .agentType(AgentType.NESSUS)
        .build()

    /** Start the Nessus endpoint */
    
    endpointService.startEndpoint(alice.endpointUrl)

    /** Establish a peer connection */
    
    val mex = MessageExchange()
        .withProtocol(RFC0434_OUT_OF_BAND_V1)
        .createOutOfBandInvitation(faber, "Faber invites Alice")
        .receiveOutOfBandInvitation(alice)
        .withProtocol(RFC0023_DIDEXCHANGE)
        .connect(alice)
        .getMessageExchange()
    
    /** Verify connection state */
    
    val peerConnection = mex.getConnection()
    
    assertNotNull(peerConnection, "No peer connection")
    assertEquals(ACTIVE, peerConnection.state)
    
    /** Send a basic message */
    
    val userMessage = "Your hovercraft is full of eels."
    
    mex.withProtocol(RFC0095_BASIC_MESSAGE)
        .sendMessage(userMessage)
    
    /** Verify message exchange state */
    
    val epm: EndpointMessage = mex.last
    assertEquals("https://didcomm.org/basicmessage/1.0/message", epm.type)
    assertEquals(userMessage, epm.bodyAsJson.selectJson("content"))
```