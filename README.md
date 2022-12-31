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