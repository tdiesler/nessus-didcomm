package org.nessus.didcomm.test.model.vc

import com.danubetech.verifiablecredentials.VerifiableCredential
import com.danubetech.verifiablecredentials.validation.Validation
import foundation.identity.jsonld.JsonLDUtils
import info.weboftrust.ldsignatures.signer.RsaSignature2018LdSigner
import info.weboftrust.ldsignatures.suites.SignatureSuites
import info.weboftrust.ldsignatures.verifier.RsaSignature2018LdVerifier
import org.junit.jupiter.api.Assertions.assertEquals
import org.junit.jupiter.api.Assertions.assertTrue
import org.junit.jupiter.api.Test
import org.nessus.didcomm.test.AbstractAgentTest
import java.net.URI

class SignCredentialTest: AbstractAgentTest() {

    @Test
    fun testSignJsonLd() {

        val verifiableCredential = VerifiableCredential.fromJson(
            readResource("/example/vc/input.vc.jsonld"))

        val verificationMethod = URI.create("did:sov:1yvXbmgPoUm4dl66D7KhyD#keys-1")
        val created = JsonLDUtils.DATE_FORMAT.parse("2018-01-01T21:19:10Z")
        val domain: String? = null
        val nonce = "c0ae1c8e-c7e7-469f-b252-86e6a0e7387e"

        val signer = RsaSignature2018LdSigner(SignatureKeys.testRSAPrivateKey)
        signer.verificationMethod = verificationMethod
        signer.created = created
        signer.domain = domain
        signer.nonce = nonce
        val ldProof = signer.sign(verifiableCredential, true, false)

        assertEquals(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018.term, ldProof.type)
        assertEquals(verificationMethod, ldProof.verificationMethod)
        assertEquals(created, ldProof.created)
        assertEquals(domain, ldProof.domain)
        assertEquals(nonce, ldProof.nonce)
        assertEquals(
            "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJSUzI1NiJ9..Sn-LB5t_x-kh9mUDq1DaS1GScj3PY_2fMnNnhq09x-ZBf6_EzYfvgFOpEvdLUwxkJiEt7B2x-LGg7bp-o7UEGCbIxWdGUTG7BGAsKsU18hUwOHrVNZ6VHovbxeFgK0iNMn0MObDiGdQbYMG8C71m3AvquUP00-2UiDcqNxmGAYg5tHv7SHXLEgvaz7SnIkBklj1yj_TMXreSGa_okbXFYxh7SkMfFcxHbBFShr0Fzd8DTn8tr_WvPHR7Tx3bkJHmqFx9Wo-0e7FkLeICsgmBKa5Hzz-y_1yEQPsDaZRRsbXfBD4krL7WTplJtAwnQ5Sy-L9cwZzNhCQC6KsggGjTgQ",
            ldProof.jws
        )

        Validation.validateJsonLd(verifiableCredential)

        val verifier = RsaSignature2018LdVerifier(SignatureKeys.testRSAPublicKey)
        val verify = verifier.verify(verifiableCredential)
        assertTrue(verify)
    }

    @Test
    fun testSignJson() {

        val verifiableCredential = VerifiableCredential.fromJson(
            readResource("/example/vc/input.vc.json"))

        val verificationMethod = URI.create("did:sov:1yvXbmgPoUm4dl66D7KhyD#keys-1")
        val created = JsonLDUtils.DATE_FORMAT.parse("2018-01-01T21:19:10Z")
        val domain: String? = null
        val nonce = "c0ae1c8e-c7e7-469f-b252-86e6a0e7387e"

        val signer = RsaSignature2018LdSigner(SignatureKeys.testRSAPrivateKey)
        signer.verificationMethod = verificationMethod
        signer.created = created
        signer.domain = domain
        signer.nonce = nonce
        val ldProof = signer.sign(verifiableCredential, true, false)

        assertEquals(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018.term, ldProof.type)
        assertEquals(verificationMethod, ldProof.verificationMethod)
        assertEquals(created, ldProof.created)
        assertEquals(domain, ldProof.domain)
        assertEquals(nonce, ldProof.nonce)
        assertEquals(
            "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJSUzI1NiJ9..GZYi1V8tbMLl5rLIZarlj-aX3KDTTqFJFtQr-2cV910J6embA7_fQPalX3pZLzld9mQ0SdJq2hlxWpMzujXKOElfWidtxJzOyp93ZsSbrtfj7fGSV_CYOSfQ7A8n3SR4O3pp6ja4vmDmBhP95oJXh_BVTbtqvU7e-_GngC2B9uoBr4JJd2mxsOu2_97u_-scPWv9xUIm5rFTGfLz5sUGbMihY96fywSATn9mD5aLDql2thHnrkfYHgsxAqQDV-gcvlZHw5-TtxN-NnG3DD5K_mugmlV3x10ZGLC5QCw0q83LGVi7NmBMShALOFtcO5CourGDSmc1jL9qA95GXMH_dA",
            ldProof.jws
        )

        Validation.validateJson(verifiableCredential)

        val verifier = RsaSignature2018LdVerifier(SignatureKeys.testRSAPublicKey)
        val verify = verifier.verify(verifiableCredential)
        assertTrue(verify)
    }
}