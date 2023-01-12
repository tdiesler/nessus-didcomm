## Nessus DIDComm

Nessus DIDComm is about digital identy and VCs based on [DIDComm](https://identity.foundation/didcomm-messaging/spec/v2.0).

[<img src="docs/img/ssi-book.png" height="200" alt="self sovereign identity">](https://www.manning.com/books/self-sovereign-identity)

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
./wallet-bootstrap --create Faber --ledger-role ENDORSER
```

The above should have created the respective siera enviroment.

### Supported Protocols

| Protocol                                      | AcaPy | Nessus |
|:----------------------------------------------|:-----:|:------:|
| [RFC0019 Encryption Envelope][rfc0019]        |       |        |
| [RFC0023 DID Exchange Protocol 1.0][rfc0023]  |   x   |        |
| [RFC0048 Trust Ping Protocol 1.0][rfc0048]    |       |        |
| [RFC0095 Basic Message Protocol 1.0][rfc0095] |   x   |        |
| [RFC0434 Out-of-Band Protocol 1.1][rfc0434]   |   x   |        |

[rfc0019]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0019-encryption-envelope
[rfc0023]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
[rfc0048]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0048-trust-ping
[rfc0095]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0095-basic-message
[rfc0434]: https://github.com/hyperledger/aries-rfcs/tree/main/features/0434-outofband
