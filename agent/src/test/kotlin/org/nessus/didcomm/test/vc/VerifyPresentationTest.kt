package org.nessus.didcomm.test.vc

import com.danubetech.keyformats.crypto.provider.Ed25519Provider
import com.danubetech.keyformats.crypto.provider.RandomProvider
import com.danubetech.keyformats.crypto.provider.SHA256Provider
import com.danubetech.keyformats.crypto.provider.impl.JavaRandomProvider
import com.danubetech.keyformats.crypto.provider.impl.JavaSHA256Provider
import com.danubetech.keyformats.crypto.provider.impl.TinkEd25519Provider
import com.danubetech.verifiablecredentials.VerifiableCredential
import com.danubetech.verifiablecredentials.VerifiablePresentation
import com.danubetech.verifiablecredentials.validation.Validation
import info.weboftrust.ldsignatures.verifier.Ed25519Signature2018LdVerifier
import org.bitcoinj.core.Base58
import org.junit.jupiter.api.Assertions
import org.nessus.didcomm.test.AbstractAgentTest

class VerifyPresentationTest: AbstractAgentTest() {

    private val publicKeyPresentation1: ByteArray = Base58.decode("DqS5F3GVe3rCxucgi4JBNagjv4dKoHc8TDLDw9kR58Pz")
    private val publicKeyPresentation2: ByteArray = Base58.decode("5yKdnU7ToTjAoRNDzfuzVTfWBH38qyhE1b9xh4v8JaWF")
    private val publicKeyCredential1: ByteArray = Base58.decode("5TVraf9itbKXrRvt2DSS95Gw4vqU3CHAdetoufdcKazA")
    private val publicKeyCredential2: ByteArray = Base58.decode("5yKdnU7ToTjAoRNDzfuzVTfWBH38qyhE1b9xh4v8JaWF")
    private val verifiablePresentationGood1 = VerifiablePresentation.fromJson(readResource("/example/vc/signed.good.vp1.jsonld"))
    private val verifiablePresentationGood2 = VerifiablePresentation.fromJson(readResource("/example/vc/signed.good.vp2.jsonld"))
    private val verifiablePresentationBad1 = VerifiablePresentation.fromJson(readResource("/example/vc/signed.bad.vp1.jsonld"))
    private val verifiablePresentationBad2 = VerifiablePresentation.fromJson(readResource("/example/vc/signed.bad.vp2.jsonld"))
    private val verifiableCredentialGood1: VerifiableCredential = verifiablePresentationGood1.verifiableCredential
    private val verifiableCredentialGood2: VerifiableCredential = verifiablePresentationGood2.verifiableCredential
    private val verifiableCredentialBad1: VerifiableCredential = verifiablePresentationBad1.verifiableCredential
    private val verifiableCredentialBad2: VerifiableCredential = verifiablePresentationBad2.verifiableCredential

    @BeforeEach
    fun before() {
        RandomProvider.set(JavaRandomProvider())
        SHA256Provider.set(JavaSHA256Provider())
        Ed25519Provider.set(TinkEd25519Provider())
    }

    @Test
    fun testValidity() {
        Validation.validateJsonLd(verifiablePresentationGood1)
        Validation.validateJsonLd(verifiablePresentationGood2)
        Validation.validateJsonLd(verifiablePresentationBad1)
        Validation.validateJsonLd(verifiablePresentationBad2)
        Validation.validateJsonLd(verifiableCredentialGood1)
        Validation.validateJsonLd(verifiableCredentialGood2)
        Validation.validateJsonLd(verifiableCredentialBad1)
        Validation.validateJsonLd(verifiableCredentialBad2)
    }

    /*
	 * GOOD CREDENTIAL
	 */
    @Test
    fun testVerifyGoodCredential1() {
        val verifier = Ed25519Signature2018LdVerifier(publicKeyCredential1)
        val verify = verifier.verify(verifiableCredentialGood1)
        Assertions.assertTrue(verify)
        Assertions.assertEquals(
            "Bachelor of Science and Arts", (verifiableCredentialGood1.credentialSubject
                .claims["degree"] as Map<*, *>?)!!["name"]
        )
    }

    @Test
    fun testVerifyGoodCredential2() {
        val verifier = Ed25519Signature2018LdVerifier(publicKeyCredential2)
        val verify = verifier.verify(verifiableCredentialGood2)
        Assertions.assertTrue(verify)
        Assertions.assertEquals(
            "Bachelor of Science and Arts", (verifiableCredentialGood1.credentialSubject
                .claims["degree"] as Map<*, *>?)!!["name"]
        )
    }

    /*
	 * BAD CREDENTIAL
	 */
    @Test
    fun testVerifyBadCredential1() {
        val verifier = Ed25519Signature2018LdVerifier(publicKeyCredential1)
        val verify = verifier.verify(verifiableCredentialBad1)
        Assertions.assertFalse(verify)
        Assertions.assertEquals(
            "Master of Science and Arts", (verifiableCredentialBad1.credentialSubject
                .claims["degree"] as Map<*, *>?)!!["name"]
        )
    }

    @Test
    fun testVerifyBadCredential2() {
        val verifier = Ed25519Signature2018LdVerifier(publicKeyCredential2)
        val verify = verifier.verify(verifiableCredentialBad2)
        Assertions.assertFalse(verify)
        Assertions.assertEquals(
            "Master of Science and Arts", (verifiableCredentialBad2.credentialSubject
                .claims["degree"] as Map<*, *>?)!!["name"]
        )
    }

    /*
	 * GOOD PRESENTATION
	 */
    @Test
    fun testVerifyGoodPresentation1() {
        val verifier = Ed25519Signature2018LdVerifier(publicKeyPresentation1)
        val verify = verifier.verify(verifiablePresentationGood1)
        Assertions.assertTrue(verify)
    }

    @Test
    fun testVerifyGoodPresentation2() {
        val verifier = Ed25519Signature2018LdVerifier(publicKeyPresentation2)
        val verify = verifier.verify(verifiablePresentationGood2)
        Assertions.assertTrue(verify)
    }

    /*
	 * BAD PRESENTATION
	 */
    @Test
    fun testVerifyBadPresentation1() {
        val verifier = Ed25519Signature2018LdVerifier(publicKeyPresentation1)
        val verify = verifier.verify(verifiablePresentationBad1)
        Assertions.assertFalse(verify)
    }

    @Test
    fun testVerifyBadPresentation2() {
        val verifier = Ed25519Signature2018LdVerifier(publicKeyPresentation2)
        val verify = verifier.verify(verifiablePresentationBad2)
        Assertions.assertFalse(verify)
    }
}