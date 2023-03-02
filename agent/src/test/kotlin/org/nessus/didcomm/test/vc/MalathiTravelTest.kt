package org.nessus.didcomm.test.vc

import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import io.kotest.matchers.shouldBe
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.w3c.W3CVerifiableCredential
import org.nessus.didcomm.w3c.W3CVerifiableValidator
import java.util.UUID


class MalathiTravelTest: AbstractAgentTest() {

    @Test
    fun validateMalathiPassportJson() {

        val governmentDid = didService.createDid(DidMethod.KEY)
        val malathiDid = didService.createDid(DidMethod.KEY)
        val airportDid = didService.createDid(DidMethod.KEY)

        // issue VC
        val mergeData = """{
          "id": "urn:uuid:${UUID.randomUUID()}",
          "issuer": "${governmentDid.uri}",
          "issuanceDate": "${dateTimeNow()}",
          "expires": "${dateTimeNow().plusYears(10)}",
          "credentialSubject": {
            "id": "${malathiDid.uri}",
            "givenName": "Malathi",
            "familyName": "Hamal",
            "citizenship": "US"
          }
        }""".decodeJson()

        val vc = W3CVerifiableCredential
            .fromPath("/example/vc/malathi-passport-vc.json")
            .merge(mergeData)

        W3CVerifiableValidator.validateSubject(vc)

        val config = ProofConfig(
            issuerDid = governmentDid.uri,
            subjectDid = malathiDid.uri,
            proofPurpose = "assertionMethod",
            proofType = ProofType.LD_PROOF)

        val signedVc = signatory.issue(vc, config, false)

        // create VP
        val vp = custodian.createPresentation(
            vcs = listOf(signedVc),
            holderDid = malathiDid.uri,
            verifierDid = airportDid.uri)

        // verify VP
        val vr = auditor.verify(vp, listOf(
            policyService.getPolicy("SignaturePolicy")))

        vr.valid shouldBe true
    }
}
