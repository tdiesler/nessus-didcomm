## Nessus DIDComm - Proof of Concept (Draft)

This POC describes the initial scope of Nessus DIDComm - an SSI agent that uses [DIDComm-2.0 ](https://identity.foundation/didcomm-messaging/spec/v2.0/)
to communicate with other agents (e.g. [Aries Cloud Agent Python](https://github.com/hyperledger/aries-cloudagent-python))

### Meet Alice, Faber and Acme

Alice, a citizen of British Columbia has graduated from Faber College some time ago. Faber College, well situated at the heart of emerging tech, 
has since adopted a form of digital transcripts that it now offers to its former students. These transcripts are verifiable credentials, 
which are a key feature of [Self Sovereign Identity](https://www.manning.com/books/self-sovereign-identity). Alice has since moved to Munich, which 
provides access to [EBSI](https://ec.europa.eu/digital-building-blocks/wikis/display/EBSI/Home) services for its citizens.

In SSI terms, Faber is an **Issuer** of verifiable credentials (VC) and Alice 
is a **Holder**. Alice may later apply for a job with Acme Corp, which then
becomes a **Verifier** in our [Trust Triangle](https://academy.affinidi.com/what-is-the-trust-triangle-9a9caf36b321)

### Agent Communication

All three parties need to agree on reliable/secure communication, which [DIDComm Messaging](https://identity.foundation/didcomm-messaging/spec/v2.0) is 
well suited for. Faber uses [AcyPy](https://github.com/hyperledger/aries-cloudagent-python) and registers the necessary cryptographic material on the 
[VON Network](https://github.com/bcgov/von-network). Alice is not known to the VON Network, neither does she have access to a [Hyperledger Aries](https://aries-interop.info/) compliant agent.
All parties communicate via DIDComm alone and use common standards to exchange information.

### POC Milestones

1. [Out of Band Invitation](https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages) from Faber to Alice and vice versa
2. [DID Exchange](https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange) between Faber & Alice
3. Alice creates peer-to-peer [Dids](https://www.w3.org/TR/did-core) to communicate with Faber and Acme
4. [Plaintext Message](https://identity.foundation/didcomm-messaging/spec/#didcomm-plaintext-messages) exchange
5. [Signed Message](https://identity.foundation/didcomm-messaging/spec/#didcomm-signed-messages) exchange 
6. [Encrypted Message](https://identity.foundation/didcomm-messaging/spec/#didcomm-encrypted-messages) exchange
7. Anything else?

### Further Work

* Support for [W3C Verifiable Credentials](https://www.w3.org/TR/vc-data-model-2.0/)
* Support for [Aries Verifiable Credentials](https://github.com/hyperledger/aries-rfcs/tree/main/features/0453-issue-credential-v2) (maybe)
* Closely work with Aries on [AIP3.0](https://hackmd.io/_Kkl9ClTRBu8W4UmZVGdUQ)
* Credential revocation
* Anything else?

### Tech Stack

* Nessus DIDComm is written in [Kotlin](https://kotlinlang.org/)
* For DIDComm Messages it uses [didcomm-jvm](https://github.com/sicpa-dlab/didcomm-jvm) from [SICPA](https://www.sicpa.com/)
* For integration with AcaPy it uses [acapy-java-client](https://github.com/hyperledger-labs/acapy-java-client)
* For integration with EBSI is uses [waltid-ssikit](https://github.com/walt-id/waltid-ssikit)
* Integration with [Apache Camel](https://camel.apache.org/) to supplement/replace [nessus-aries](https://github.com/tdiesler/nessus-aries)

PRs, Issues, Comments all welcome

cheers
-- thomas