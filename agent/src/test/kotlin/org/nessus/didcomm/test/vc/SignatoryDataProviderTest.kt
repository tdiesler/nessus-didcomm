package org.nessus.didcomm.test.vc

import id.walt.credentials.w3c.VerifiableCredential
import id.walt.credentials.w3c.builder.W3CCredentialBuilder
import id.walt.credentials.w3c.templates.VcTemplate
import id.walt.signatory.Ecosystem
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import id.walt.signatory.SignatoryDataProvider
import id.walt.signatory.dataproviders.MergingDataProvider
import mu.KotlinLogging
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.encodeJson

class SignatoryDataProviderTest: AbstractAgentTest() {
    private val log = KotlinLogging.logger {}

    @Test
    fun testMergingDataProvider() {
        val issuerDid = didService.createDid(DidMethod.KEY)
        val subjectDid = didService.createDid(DidMethod.KEY)

        val vcTemplate: VcTemplate = templateService.getTemplate("VerifiableId")
        val partialBuilder = W3CCredentialBuilder.fromPartial(vcTemplate.template!!)

        val config = ProofConfig(
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
        )

        val dataProvider: SignatoryDataProvider = MergingDataProvider(mapOf(
            "credentialSubject" to mapOf(
                "firstName" to "Miss",
                "familyName" to "Piggy",
                "gender" to "Female",
                "nameAndFamilyNameAtBirth" to "Baby Piglet",
                "currentAddress" to mapOf(
                    "currentAddress" to "Sesame Street 123",
                ),
                "dateOfBirth" to "1969-11-10",
                "placeOfBirth" to "Leland, Mississippi"
            )
        ))

        val vc: VerifiableCredential = dataProvider.populate(partialBuilder, config).build()
        log.info { "VerifiableCredential: ${vc.encodeJson(true)}" }
    }
}
