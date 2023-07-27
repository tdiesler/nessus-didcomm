package org.nessus.didcomm.test.model.vc

import io.kotest.matchers.shouldBe
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.model.W3CVerifiableCredentialValidator.validateCredential
import org.nessus.didcomm.model.W3CVerifiableCredentialValidator.validatePresentation
import org.nessus.didcomm.model.W3CVerifiablePresentation
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.trimJson

class VCValidationTest: AbstractAgentTest() {

    @Test
    fun testVerifiableCredential() {
        for (path in listOf(
                "/vc/input.vc.json",
                "/vc/input.vc.jsonld",
                "/vc/passport.vc.json",
                "/vc/signed.bad.vc.jsonld",
                "/vc/signed.good.vc.jsonld")) {

            val expJson = readResource(path).trimJson()

            val vc = W3CVerifiableCredential.fromJson(expJson)
            val result = validateCredential(vc, false)
            result.isSuccess shouldBe true
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

            val vp = W3CVerifiablePresentation.fromJson(expJson)
            val result = validatePresentation(vp, false)
            result.isSuccess shouldBe true
        }
    }

    @Test
    fun testCredentialSchema() {

        val path = "/vc/credentialSchema.vc.json"
        val expJson = readResource(path).trimJson()

        val vc = W3CVerifiableCredential.fromJson(expJson)
        val result = validateCredential(vc, false)
        result.isSuccess shouldBe true
    }

    @Test
    fun testCredentialStatus() {

        val path = "/vc/credentialStatus.vc.json"
        val expJson = readResource(path).trimJson()

        val vc = W3CVerifiableCredential.fromJson(expJson)
        val result = validateCredential(vc, false)
        result.isSuccess shouldBe true
    }
}