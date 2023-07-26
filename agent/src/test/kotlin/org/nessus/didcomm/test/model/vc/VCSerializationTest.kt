package org.nessus.didcomm.test.model.vc

import io.kotest.matchers.shouldBe
import org.nessus.didcomm.model.CredentialSchema
import org.nessus.didcomm.model.CredentialStatus
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.model.W3CVerifiablePresentation
import org.nessus.didcomm.model.WaltIdVerifiableCredential
import org.nessus.didcomm.model.WaltIdVerifiablePresentation
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.trimJson

class VCSerializationTest: AbstractAgentTest() {

    @Test
    fun testVerifiableCredential() {
        for (path in listOf(
                "/vc/input.vc.json",
                "/vc/input.vc.jsonld",
                "/vc/passport.vc.json",
                "/vc/signed.bad.vc.jsonld",
                "/vc/signed.good.vc.jsonld")) {

            val expJson = readResource(path).trimJson()

            val nessusVC = W3CVerifiableCredential.fromJson(expJson)
            nessusVC.toJson() shouldBe expJson
            nessusVC.encodeJson() shouldBe expJson

            val waltVC = WaltIdVerifiableCredential.fromJson(expJson)
            waltVC.toJson().decodeJson() shouldBe nessusVC.toMap()
        }
    }

    @Test
    fun testVerifiablePresentation() {
        for (path in listOf(
                "/vc/input.vp.jsonld",
                "/vc/signed.bad.vp1.jsonld",
                "/vc/signed.bad.vp2.jsonld",
                "/vc/signed.good.vp1.jsonld",
                "/vc/signed.good.vp2.jsonld")) {

            val expJson = readResource(path).trimJson()

            val nessusVP = W3CVerifiablePresentation.fromJson(expJson)
            nessusVP.toJson() shouldBe expJson
            nessusVP.encodeJson() shouldBe expJson

            val waltVP = WaltIdVerifiablePresentation.fromJson(expJson)
            waltVP.toJson().decodeJson() shouldBe nessusVP.toMap()
        }
    }

    @Test
    fun testCredentialSchema() {

        val path = "/vc/credentialSchema.vc.json"
        val expJson = readResource(path).trimJson()

        val nessusVC = W3CVerifiableCredential.fromJson(expJson)
        nessusVC.toJson() shouldBe expJson

        val waltVC = WaltIdVerifiableCredential.fromJson(expJson)
        waltVC.toJson().decodeJson() shouldBe nessusVC.toMap()

        nessusVC.credentialSchema.single() shouldBe CredentialSchema.fromJson("""{
            "id": "https://example.org/examples/degree.json",
            "type": "JsonSchemaValidator2018"
        }""".trimIndent())
    }

    @Test
    fun testCredentialStatus() {

        val path = "/vc/credentialStatus.vc.json"
        val expJson = readResource(path).trimJson()

        val nessusVC = W3CVerifiableCredential.fromJson(expJson)
        nessusVC.toJson() shouldBe expJson

        val waltVC = WaltIdVerifiableCredential.fromJson(expJson)
        waltVC.toJson().decodeJson() shouldBe nessusVC.toMap()

        nessusVC.credentialStatus shouldBe CredentialStatus.fromJson("""{
            "id":"https://example.edu/credential/status/assertionMethod#14",
            "type":"StatusList2021Entry",
            "statusListIndex":"14",
            "statusPurpose":"assertionMethod",
            "statusListCredential":"data/revocation/assertionMethod.cred"
        }""".trimIndent())
    }
}