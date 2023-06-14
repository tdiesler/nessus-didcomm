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

### Supported Protocols

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

### CLI Example

Creating a peer connection between Faber (AcaPy) and Alice (Nessus)

```shell
$ didcomm

Nessus DIDComm CLI
Version: 23.2.1

>> wallet list
Government [agent=AcaPy, type=INDY, url=http://192.168.0.10:8031]

>> wallet create --name=Faber --agent=AcaPy
Wallet created: Faber [agent=AcaPy, type=IN_MEMORY, url=http://192.168.0.10:8030]

Faber>> wallet create --name=Alice 
Wallet created: Alice [agent=Nessus, type=IN_MEMORY, url=http://192.168.0.10:9000]

Alice>> agent start
Started Camel endpoint on 192.168.0.10:9000

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

### Docker Example

You can run a headless Nessus agent endpoint like this ...

```shell
docker run --detach --name didcomm \
  -p 9100:9100 \
  -e NESSUS_USER_PORT=9100 \
  nessusio/nessus-didcomm:dev \
    run --headless script/travel-with-minor-bootstrap.txt

docker logs -fn400 didcomm
````

or a local interactive shell like this ...

```shell
docker run -it --name=didcomm \
  -p 9000:9000 \
  -e NESSUS_USER_HOST=$EXTERNAL_IP \
  -e NESSUS_USER_PORT=9000 \
  nessusio/nessus-didcomm:dev agent start
````

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
### Build the Project

The build currently depends on a number of external (snapshot) projects that need to be built first

#### Build WaltId - SSI Kit

Build with JDK11

```
find ~/.m2/repository/id/walt -name "*.jar"

git clone https://github.com/tdiesler/waltid-ssikit.git
git checkout nessus
./gradlew clean test publishToMavenLocal
```

#### Build Sicpa - DIDComm JVM & PeerDID

Build with JDK11

```
find ~/.m2/repository/org/didcommx -name "*.jar"

git clone https://github.com/tdiesler/didcomm-jvm.git
git checkout nessus
./gradlew clean test publishToMavenLocal

git clone https://github.com/tdiesler/peer-did-jvm.git
git checkout nessus
./gradlew clean test publishToMavenLocal
```

#### Build Danube Tech - Verifiable Credentials 

```
find ~/.m2/repository/com/danubetech -name "*.jar"

git clone https://github.com/tdiesler/verifiable-credentials-java.git
git checkout nessus
mvn clean install
```