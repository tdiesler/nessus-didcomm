package org.nessus.didcomm.test.vc

import id.walt.auditor.Auditor
import id.walt.auditor.VerificationPolicy
import id.walt.auditor.VerificationResult
import id.walt.credentials.w3c.VerifiableCredential
import id.walt.credentials.w3c.VerifiablePresentation
import id.walt.credentials.w3c.W3CIssuer
import id.walt.credentials.w3c.toVerifiableCredential
import id.walt.credentials.w3c.toVerifiablePresentation
import id.walt.custodian.Custodian
import id.walt.signatory.Ecosystem
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import id.walt.signatory.SignatoryDataProvider
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.dateTimeNow
import java.time.Instant
import java.util.Collections.max

class VerifiableCredentialTest: AbstractAgentTest() {
    private val log = KotlinLogging.logger {}

    @Test
    fun issuePresentVerify_VerifiableId() {

        val issuerDid = didService.createDid(DidMethod.KEY)
        val holderDid = didService.createDid(DidMethod.KEY)
        val verifierDid = didService.createDid(DidMethod.KEY)

        val vc = issueCredential("VerifiableId", issuerDid, holderDid)
        val vp = createPresentation(holderDid, verifierDid, "proofDomain", "1234", vc)

        val policies = listOf(
            policyService.getPolicy("SignaturePolicy"),
            policyService.getPolicyWithJsonArg("ChallengePolicy", """{"challenges": ["1234"], "applyToVC": false}"""))

        val verificationResult = verifyPresentation(vp, policies)
        verificationResult.valid shouldBe true
    }

    private fun issueCredential(
        template: String,
        issuerDid: Did,
        subjectDid: Did
    ): VerifiableCredential {

        val issuerDidDoc = didService.loadDidDocument(issuerDid.uri)
        log.debug { "Issuer DidDoc:\n${issuerDidDoc.encodeJson(true)}" }

        val subjectDidDoc = didService.loadDidDocument(subjectDid.uri)
        log.debug { "Subject DidDoc:\n${subjectDidDoc.encodeJson(true)}" }

        log.info { "Issuing a verifiable credential (using template $template)..." }
        val vcStr: String = signatory.issue(
            templateIdOrFilename = template,
            config = ProofConfig(
                issuerDid = issuerDid.uri,
                subjectDid = subjectDid.uri,
                verifierDid = null,
                proofType = ProofType.LD_PROOF,

                // [TODO] what are these
                // https://github.com/tdiesler/nessus-didcomm/issues/89
                domain = null,
                nonce = null,
                proofPurpose = null,
                credentialId = null,

                issueDate = dateTimeNow().toInstant(),
                validDate = null,
                expirationDate = null,
                dataProviderIdentifier = null, // may be used for mapping data-sets from a custom data-provider
                ldSignatureType = null,
                creator = issuerDid.uri,
                ecosystem = Ecosystem.DEFAULT
            ),
            dataProvider = null as SignatoryDataProvider?,
            issuer = null as W3CIssuer?,
            storeCredential = false
        )

        log.info("Results: ...")
        log.info("Issuer $issuerDid.uri issued a $template to Holder ${subjectDid.uri}")
        log.info("Credential document (below, JSON):\n\n$vcStr")

        return vcStr.toVerifiableCredential()
    }

    private fun createPresentation(
        holderDid: Did,
        verifierDid: Did,
        domain: String?,
        challenge: String,
        vc: VerifiableCredential
    ): VerifiablePresentation {
        log.info("Creating a verifiable presentation for DID $holderDid ...")

        val custodian = Custodian.getService()
        val vpStr = custodian.createPresentation(
            vcs = listOf(vc.toJson()),
            holderDid = holderDid.uri,
            verifierDid = verifierDid.uri,
            domain = domain,
            challenge = challenge,
            expirationDate = null as Instant?)

        log.info("Results: ...")
        log.info("Verifiable presentation generated for holder DID: $holderDid")
        log.info("Verifiable presentation document (below, JSON):\n\n$vpStr")
        return vpStr.toVerifiablePresentation()
    }

    private fun verifyPresentation(vp: VerifiablePresentation, policies: List<VerificationPolicy>): VerificationResult {
        val verificationResult = Auditor.getService().verify(vp.toJson(), policies)

        log.info("Results ...")
        val maxIdLength = max(policies.map { it.id.length })
        verificationResult.policyResults.forEach { (policy, result) ->
            log.info("${policy.padEnd(maxIdLength)} - $result")
        }
        log.info("${"Verified".padEnd(maxIdLength)} - ${verificationResult.valid}")
        return verificationResult
    }
}
