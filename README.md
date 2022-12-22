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

This project requires access to a Hyperledger Indy Network. Is is recommended to use the [VON Network](https://github.com/bcgov/von-network), developed as a portable Indy Node Network implementation for local development. Instructions for setting up the von-network can be viewed [here](https://github.com/bcgov/von-network#running-the-network-locally).

Basic instructions for using the VON Network are [here](https://github.com/bcgov/von-network/blob/main/docs/UsingVONNetwork.md).

### Start Hyperledger Aries Cloud Agent

Use this when you want to run the tests.

```
docker compose up --detach && docker compose logs -f acapy
```

### Onboarding

```
./aries-wallet --create Government --ledger-role TRUSTEE
./aries-wallet --create Faber --ledger-role ENDORSER
./aries-wallet --create Alice
```

or 

```
./aries-wallet --create-all
```

### Siera CLI

[Siera](https://siera.animo.id/) makes self-sovereign identity development easier  

The above should have created the respective siera enviroments. Let's see ... 

```
brew tap animo/siera
brew install animo/agent-cli/siera

siera configuration view

Configuration path: ~/.config/siera/config.yaml
---
configurations:
  Acme:
    endpoint: "http://localhost:8031"
    api_key: adminkey
    auth_token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ3YWxsZXRfaWQiOiI0NTdjMjk4Yy01ODg1LTQ0MTctYjFhYS1kN2NjMDNmZmQ3ZDEiLCJpYXQiOjE2NzE3MjgyMDJ9.625-hTW9XPGS_Z5VNKE0IasnGg0lV_TqCMR3TDPWxkc
    agent: aca-py
  Alice:
    endpoint: "http://localhost:8031"
    api_key: adminkey
    auth_token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ3YWxsZXRfaWQiOiJiZmY1NWJlNy0yMTc5LTQzNGQtYjEwZC1mZTNlOTEyODM0MjkiLCJpYXQiOjE2NzE3MjgyMTR9.GpP5ltTyc-mQPMKzsoNM74sxoigXnDqR2WRJkEKjLG8
    agent: aca-py
  Faber:
    endpoint: "http://localhost:8031"
    api_key: adminkey
    auth_token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ3YWxsZXRfaWQiOiI0MGQ3OWY5ZC1jNWQyLTQ3YWItOGE4NS1lNGQ3YjVjZDMwNTAiLCJpYXQiOjE2NzE3MjgxODl9.h7wrw0VslLYJnswz1KT9LMXGrWLRzL6NLlY7sgfEbwk
    agent: aca-py
  Government:
    endpoint: "http://localhost:8031"
    api_key: adminkey
    auth_token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ3YWxsZXRfaWQiOiJlZWQyMjNhZS0wYTNmLTQ0MDUtOGI4NS0wMzBlM2E5OGVjZGUiLCJpYXQiOjE2NzE3MjgxNzZ9.B3wRMTJ2iv0KwwOyWnKgv0h1njm-OIi1izCgaM5Cj_w
    agent: aca-py
```