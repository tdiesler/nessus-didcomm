package org.nessus.didcomm.test.vc

import id.walt.auditor.Auditor
import id.walt.auditor.PolicyRegistry
import id.walt.custodian.Custodian
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.trimJson

class VerifiableCredentialTest: AbstractAgentTest() {
    private val log = KotlinLogging.logger {}

    @Test
    fun issueVerifiableId_SignaturePolicy() {

        val issuerDid = didService.createDid(DidMethod.KEY)
        val holderDid = didService.createDid(DidMethod.KEY)
        val verifierDid = didService.createDid(DidMethod.KEY)

        val issuerDidDoc = didService.loadDidDocument(issuerDid.uri)
        val issuerAssertionMethod = issuerDidDoc.assertionMethods.first()

        // issue VC
        val vc = signatory.issue(
            templateIdOrFilename = "VerifiableId",
            config = ProofConfig(
                issuerDid = issuerDid.uri,
                subjectDid = holderDid.uri,
                proofPurpose = "assertionMethod",
                issuerVerificationMethod = issuerAssertionMethod,
                proofType = ProofType.LD_PROOF)
        )

        // create VP
        val vp = Custodian.getService().createPresentation(
            vcs = listOf(vc),
            holderDid = holderDid.uri,
            verifierDid = verifierDid.uri)

        // verification policies
        val policy = PolicyRegistry.getPolicy("SignaturePolicy")

        // verify VP
        val vr = Auditor.getService().verify(vp, listOf(policy))
        vr.valid shouldBe true
    }

    @Test
    fun issueVerifiableId_ChallengePolicy() {

        val issuerDid = didService.createDid(DidMethod.KEY)
        val holderDid = didService.createDid(DidMethod.KEY)
        val verifierDid = didService.createDid(DidMethod.KEY)

        val issuerDidDoc = didService.loadDidDocument(issuerDid.uri)
        val issuerAssertionMethod = issuerDidDoc.assertionMethods.first()

        // issue VC
        val vc = signatory.issue(
            templateIdOrFilename = "VerifiableId",
            config = ProofConfig(
                issuerDid = issuerDid.uri,
                subjectDid = holderDid.uri,
                proofPurpose = "assertionMethod",
                issuerVerificationMethod = issuerAssertionMethod,
                proofType = ProofType.LD_PROOF)
        )

        // create VP
        val vp = Custodian.getService().createPresentation(
            vcs = listOf(vc),
            holderDid = holderDid.uri,
            verifierDid = verifierDid.uri,
            challenge = "1234",
        )

        // verification policies
        val policy = policyService.getPolicyWithJsonArg("ChallengePolicy",
            """{ "challenges": ["1234"], "applyToVC": false }""".trimJson())

        // verify VP
        val vr = Auditor.getService().verify(vp, listOf(policy))
        vr.valid shouldBe true
    }

    @Test
    fun issueVerifiableId_DynamicPolicy() {

        val issuerDid = didService.createDid(DidMethod.KEY)
        val holderDid = didService.createDid(DidMethod.KEY)
        val verifierDid = didService.createDid(DidMethod.KEY)

        val issuerDidDoc = didService.loadDidDocument(issuerDid.uri)
        val issuerAssertionMethod = issuerDidDoc.assertionMethods.first()

        // issue VC
        val vc = signatory.issue(
            templateIdOrFilename = "VerifiableId",
            config = ProofConfig(
                issuerDid = issuerDid.uri,
                subjectDid = holderDid.uri,
                proofPurpose = "assertionMethod",
                issuerVerificationMethod = issuerAssertionMethod,
                proofType = ProofType.LD_PROOF)
        )

        // create VP
        val vp = Custodian.getService().createPresentation(
            vcs = listOf(vc),
            holderDid = holderDid.uri,
            verifierDid = verifierDid.uri,
        )

        // verification policies
        val policy = policyService.getPolicyWithJsonArg("DynamicPolicy",
            """{
                "input": { "user": "${holderDid.uri}" },
                "policy": "src/test/resources/rego/subject-policy.rego"
            }""".trimJson())

        // verify VP
        val vr = Auditor.getService().verify(vp, listOf(policy))
        vr.valid shouldBe true
    }
}
