/*-
 * #%L
 * Nessus DIDComm :: ITests
 * %%
 * Copyright (C) 2022 Nessus
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package org.nessus.didcomm.test.json

import id.walt.credentials.w3c.VerifiableCredential
import id.walt.credentials.w3c.VerifiablePresentation
import org.nessus.didcomm.json.RpcContext
import org.nessus.didcomm.json.model.VCData
import org.nessus.didcomm.json.model.VPData
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.model.WalletRole
import org.nessus.didcomm.util.toValueMap


class AttachmentContext: RpcContext() {

    fun connection(invtr: String, invee: String): Connection {
        return getAttachment("${invtr}_${invee}_Connection", Connection::class) as Connection
    }

    fun wallet(name: String): Wallet {
        return getAttachment(name, Wallet::class) as Wallet
    }
}

/**
 * It should be possible to drive Nessus DIDComm entirely through JSON-RPC
 */
class FaberAcmeThriftTest: AbstractJsonRpcTest() {

    @BeforeAll
    fun startAgent() {
        startNessusEndpoint()
    }

    @Test
    fun faberAcmeThrift() {

        val ctx = AttachmentContext()
        try {

            /*
             * Onboard Government Wallet and DID
             *
             * Trustees operate nodes. Trustees govern the network. These are the highest
             * privileged DIDs. Endorsers are able to write Schemas and Credential Definitions
             * to the ledger, or sign such transactions, so they can be written by non-privileged DIDs.
             *
             * We want to ensure a DID has the least amount of privilege it needs to
             * operate, which in many cases is no privilege, provided the resources it needs
             * are already written to the ledger, either by a privileged DID or by having
             * the txn signed by a privileged DID (e.g. by an Endorser).
             *
             * An Endorser is a person or organization that the ledger already knows about,
             * that is able to help bootstrap others.
             */

            onboardWallet(ctx, "Government", WalletRole.TRUSTEE)

            /*
             * Onboarding Faber, Acme, Thrift
             *
             * Each connection is actually a pair of Pairwise-Unique Identifiers (DIDs). The
             * one DID is owned by one party to the connection and the second by another.
             *
             * Both parties know both DIDs and understand what connection this pair
             * describes.
             *
             * Publishing with a DID verification key allows a person, organization or
             * thing, to verify that someone owns this DID as that person, organization or
             * thing is the only one who knows the corresponding signing key and any
             * DID-related operations requiring signing with this key.
             *
             * The relationship between them is not shareable with others; it is unique to
             * those two parties in that each pairwise relationship uses different DIDs.
             *
             * We call the process of establish a connection Onboarding.
             */

            val faber = onboardWallet(ctx, "Faber", WalletRole.ENDORSER)
            val acme = onboardWallet(ctx, "Acme", WalletRole.ENDORSER)
            val thrift = onboardWallet(ctx, "Thrift", WalletRole.ENDORSER)
            val alice = onboardWallet(ctx, "Alice", WalletRole.USER)

            /*
             * [TODO] Creating Credential Schemas
             *
             * Credential Schema is the base semantic structure that describes the list of
             * attributes which one particular Credential can contain.
             *
             * It’s not possible to update an existing Schema. If the Schema needs to be
             * evolved, a new Schema with a new version or name needs to be created.
             *
             * Schemas in Nessus are JSON Schema documents that specify their name and
             * version, and that list attributes that will appear in a credential.
             * Currently, they do not describe data type, recurrence rules, nesting, and
             * other elaborate constructs.
             */

            // Support message validation against multiple json schema docs
            // https://github.com/tdiesler/nessus-didcomm/issues/141

            // Note, currently we rely on all-encompassing schemas
            // that can be found on the classpath

            // createTranscriptSchema(ctx)
            // createJobCertificateSchema(ctx)

            /*
             * [TODO] In AcaPy there is a concept ot "Credential Definition"
             * (add here for information only)
             *
             * Creating Credential Definitions
             *
             * Credential Definition is similar in that the keys that the Issuer uses for
             * the signing of Credentials also satisfies a specific Credential Schema.
             *
             * It references it's associated schema, announces who is going to be issuing
             * credentials with that schema, what type of signature method they plan to use
             * (“CL” = “Camenisch Lysyanskya”, the default method used for zero-knowledge
             * proofs by indy), how they plan to handle revocation, and so forth.
             *
             * It’s not possible to update data in an existing Credential Definition. If a
             * CredDef needs to be evolved (for example, a key needs to be rotated), then a
             * new Credential Definition needs to be created by a new Issuer DID.
             *
             * A Credential Definition can be created and saved in the Ledger an Endorser.
             */

            // createTranscriptCredentialDefinition(ctx)
            // createJobCertificateCredentialDefinition(ctx)

            /*
             * Create a peer connection between Faber/Alice
             *
             * Faber create a new DID for Alice to use for this Peer Connection
             */

            val faberAliceCon = peerConnect(ctx, "Faber", "Alice")

            /*
             * Alice gets her Transcript from Faber College
             *
             * A credential is a piece of information about an identity — a name, an age, a
             * credit score... It is information claimed to be true. In this case, the
             * credential is named, “Transcript”.
             *
             * Credentials are offered by an issuer.
             *
             * An issuer may be any identity owner known to the Ledger and any issuer may
             * issue a credential about any identity owner it can identify.
             *
             * The usefulness and reliability of a credential are tied to the reputation of
             * the issuer with respect to the credential at hand. For Alice to self-issue a
             * credential that she likes chocolate ice cream may be perfectly reasonable,
             * but for her to self-issue a credential that she graduated from Faber College
             * should not impress anyone.
             */

            issueCredential(ctx,
                issuer = "Faber",
                holder = "Alice",
                template = "UniversityTranscript",
                subjectData = """
                {
                  "givenName": "Alice",
                  "familyName": "Garcia",
                  "ssn": "123-45-6789",
                  "degree": "Bachelor of Science, Marketing",
                  "status": "graduated",
                  "year": "2015",
                  "average": "5"
                }                
                """.toValueMap())

            alice.findVerifiableCredentialsByType("UniversityTranscript")
                .first { "${it.credentialSubject?.id}" == faberAliceCon.theirDid.uri }

            /*
             * Create a peer connection between Acme/Alice
             *
             *  Alice does not connect to Faber's public DID, Alice does not even have a public DID
             *  Instead both parties create new DIDs that they use for their peer connection
             */

            val acmeAliceCon = peerConnect(ctx, "Acme", "Alice")

            /*
             * Alice applies for a job at Acme
             *
             * At some time in the future, Alice would like to work for Acme Corp. Normally
             * she would browse to their website, where she would click on a hyperlink to
             * apply for a job. Her browser would download a connection request, which she
             * can open in her digital wallet; this would trigger a prompt to Alice, asking
             * her to accept the connection with Acme Corp.
             *
             * After Alice had established connection with Acme, she got the Job-Application
             * Proof Request. A proof request is a request made by the party who needs
             * verifiable proof of having certain attributes and the solving of predicates
             * that can be provided by other verified credentials.
             *
             * Acme Corp is requesting that Alice provide a Job Application. The Job
             * Application requires a name, degree, status, SSN and also the satisfaction of
             * the condition about the average mark or grades.
             */

            requestPresentation(ctx,
                verifier = "Acme",
                prover = "Alice",
                template = "UniversityTranscript")

            acme.findVerifiablePresentationsByType("UniversityTranscript")
                .first { "${it.subjectId}" == acmeAliceCon.theirDid.uri }

            /*
             * Alice gets the job and hence receives a JobCertificate from Acme
             *
             * This is similar to the Transcript VC that she got from Faber, except that the
             * JobCertificate credential can be revoked by Acme
             */

            issueCredential(ctx,
                issuer = "Acme",
                holder = "Alice",
                template = "JobCertificate",
                subjectData = """
                {
                  "givenName": "Alice",
                  "familyName": "Garcia",
                  "employee_status": "permanent",
                  "salary": "2500"
                }                
                """.toValueMap())

            alice.findVerifiableCredentialsByType("JobCertificate")
                .first { "${it.credentialSubject?.id}" == acmeAliceCon.theirDid.uri }

            /*
             * Create a peer connection between Alice/Thrift
             *
             * Alice does not connect to Thrift's public DID, Alice does not even have a public DID
             * Instead both parties create new DIDs that they use for their peer connection
             */

            val thriftAliceCon = peerConnect(ctx, "Thrift", "Alice")

            /*
             * Alice applies for a loan with Thrift Bank
             *
             * Now that Alice has a job, she’d like to apply for a loan. That will require a
             * proof of employment. She can get this from the Job-Certificate credential
             * offered by Acme.
             */

            requestPresentation(ctx,
                verifier = "Thrift",
                prover = "Alice",
                template = "JobCertificate")

            thrift.findVerifiablePresentationsByType("JobCertificate")
                .first { "${it.subjectId}" == thriftAliceCon.theirDid.uri }

            /*
             * Thrift accepts the loan application and now requires KYC
             *
             * Thrift Bank sends the second Proof Request where Alice needs to share her
             * personal information with the bank.
             */

            requestPresentation(ctx,
                verifier = "Thrift",
                prover = "Alice",
                template = "JobCertificate")

            thrift.findVerifiablePresentationsByType("JobCertificate")
                .first { "${it.subjectId}" == thriftAliceCon.theirDid.uri }

            /*
             * Alice decides to quit her job with Acme
             */

//        acmeRevokesTheJobCertificate(ctx)

            /*
             * Alice applies for another loan with Thrift Bank - this time without having a Job
             *
             */

//        applyForLoanWithThrift(ctx, false)

        } finally {
            removeWallets(ctx)
        }
    }

    private fun peerConnect(ctx: AttachmentContext, inviter: String, invitee: String): Connection {
        return peerConnect(ctx.wallet(inviter), ctx.wallet(invitee)).also { pcon ->
            ctx.putAttachment("${inviter}_${invitee}_Connection", Connection::class, pcon)
        }
    }

    private fun issueCredential(ctx: AttachmentContext, issuer: String, holder: String, template: String, subjectData: Map<String, Any>): VerifiableCredential {
        val pcon = ctx.connection(issuer, holder)
        val holderDid = pcon.theirDid
        val data = VCData(
            issuerId = ctx.wallet(issuer).id,
            holderDid = holderDid.uri,
            template = template,
            subjectData = subjectData)
        return issueCredential(data).also { vc ->
            ctx.putAttachment("${issuer}_${holder}_${template}_VC", VerifiableCredential::class, vc)
        }
    }

    private fun requestPresentation(ctx: AttachmentContext, verifier: String, prover: String, template: String): VerifiablePresentation {
        val pcon = ctx.connection(verifier, prover)
        val proverDid = pcon.theirDid
        val data = VPData(
            verifierId = ctx.wallet(verifier).id,
            proverDid = proverDid.uri,
            template = template)
        return requestPresentation(data).also { vc ->
            ctx.putAttachment("${prover}_${verifier}_${template}_VP", VerifiablePresentation::class, vc)
        }
    }

    private fun onboardWallet(ctx: AttachmentContext, name: String, role: WalletRole): Wallet {
        return createWallet(name, role).also { wallet ->
            ctx.putAttachment(name, Wallet::class, wallet)
        }
    }

    private fun removeWallets(ctx: AttachmentContext) {
        ctx.attachmentKeys.filter { it.type == Wallet::class }.forEach {
            removeWallet(ctx.getAttachment(it) as Wallet)
            ctx.removeAttachment(it)
        }
    }
}
