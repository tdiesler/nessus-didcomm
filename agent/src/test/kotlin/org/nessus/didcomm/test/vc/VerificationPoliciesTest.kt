package org.nessus.didcomm.test.vc

import id.walt.custodian.Custodian
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.trimJson
import org.nessus.didcomm.model.W3CVerifiableCredential

class VerificationPoliciesTest: AbstractAgentTest() {
    private val log = KotlinLogging.logger {}

    @Test
    fun issueVerifiableId_SignaturePolicy() {

        val issuerDid = didService.createDid(DidMethod.KEY)
        val holderDid = didService.createDid(DidMethod.KEY)
        val verifierDid = didService.createDid(DidMethod.KEY)

        val vc = W3CVerifiableCredential
            .fromTemplate("VerifiableId",
                """{
                    "issuer": "${issuerDid.uri}",
                    "credentialSubject": {
                        "id": "${holderDid.uri}"
                    }
                }""".decodeJson())
            .validate()

        val config = ProofConfig(
            issuerDid = issuerDid.uri,
            subjectDid = holderDid.uri,
            proofPurpose = "assertionMethod",
            proofType = ProofType.LD_PROOF)

        val signedVc = signatory.issue(vc, config, false)

        // create VP
        val vp = custodian.createPresentation(
            vcs = listOf(signedVc.encodeJson()),
            holderDid = holderDid.uri,
            verifierDid = verifierDid.uri)

        // verify VP
        val vr = auditor.verify(vp, listOf(
            policyService.getPolicy("SignaturePolicy")))

        vr.result shouldBe true
    }

    @Test
    fun issueVerifiableId_ChallengePolicy() {

        val issuerDid = didService.createDid(DidMethod.KEY)
        val holderDid = didService.createDid(DidMethod.KEY)
        val verifierDid = didService.createDid(DidMethod.KEY)

        // issue VC
        val vc = W3CVerifiableCredential
            .fromTemplate("VerifiableId",
                """{
                    "issuer": "${issuerDid.uri}",
                    "credentialSubject": {
                        "id": "${holderDid.uri}"
                    }
                }""".decodeJson())
            .validate()

        val config = ProofConfig(
            issuerDid = issuerDid.uri,
            subjectDid = holderDid.uri,
            proofPurpose = "assertionMethod",
            proofType = ProofType.LD_PROOF)

        val signedVc = signatory.issue(vc, config, false)

        // create VP
        val vp = custodian.createPresentation(
            vcs = listOf(signedVc.encodeJson()),
            holderDid = holderDid.uri,
            verifierDid = verifierDid.uri,
            challenge = "1234",
        )

        // verification policies
        val policy = policyService.getPolicyWithJsonArg("ChallengePolicy",
            """{ "challenges": ["1234"], "applyToVC": false }""".trimJson())

        // verify VP
        val vr = auditor.verify(vp, listOf(policy))
        vr.result shouldBe true
    }

    @Test
    fun issueVerifiableId_DynamicPolicy() {

        val issuerDid = didService.createDid(DidMethod.KEY)
        val holderDid = didService.createDid(DidMethod.KEY)
        val verifierDid = didService.createDid(DidMethod.KEY)

        // issue VC
        val mergeData = """{
          "issuer": "${issuerDid.uri}",
          "credentialSubject": {
            "id": "${holderDid.uri}"
          }
        }""".decodeJson()

        val vc = W3CVerifiableCredential
            .fromTemplate("VerifiableId", mergeData)
            .validate()

        val config = ProofConfig(
            issuerDid = issuerDid.uri,
            subjectDid = holderDid.uri,
            proofPurpose = "assertionMethod",
            proofType = ProofType.LD_PROOF)

        val signedVc = signatory.issue(vc, config, false)

        // create VP
        val vp = Custodian.getService().createPresentation(
            vcs = listOf(signedVc.encodeJson()),
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
        val vr = auditor.verify(vp, listOf(policy))
        vr.result shouldBe true
    }
}
