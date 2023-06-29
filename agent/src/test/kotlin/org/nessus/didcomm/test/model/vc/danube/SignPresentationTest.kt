package org.nessus.didcomm.test.model.vc.danube

import com.danubetech.verifiablecredentials.validation.Validation
import foundation.identity.jsonld.JsonLDUtils
import info.weboftrust.ldsignatures.signer.RsaSignature2018LdSigner
import info.weboftrust.ldsignatures.suites.SignatureSuites
import info.weboftrust.ldsignatures.verifier.RsaSignature2018LdVerifier
import io.javalin.core.util.FileUtil.readResource
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test
import org.nessus.didcomm.model.DanubeTechVerifiablePresentation
import org.nessus.didcomm.test.model.vc.SignatureKeys
import java.net.URI

class SignPresentationTest {

    @Test
    fun testSignLd() {
        val verifiablePresentation = DanubeTechVerifiablePresentation.fromJson(
            readResource("/vc/input.vp.jsonld"))

        val verificationMethod = URI.create("did:sov:1yvXbmgPoUm4dl66D7KhyD#keys-1")
        val created = JsonLDUtils.DATE_FORMAT.parse("2018-01-01T21:19:10Z")
        val domain: String? = null
        val nonce = "c0ae1c8e-c7e7-469f-b252-86e6a0e7387e"

        val signer = RsaSignature2018LdSigner(SignatureKeys.testRSAPrivateKey)
        signer.verificationMethod = verificationMethod
        signer.created = created
        signer.domain = domain
        signer.nonce = nonce
        val ldSignature = signer.sign(verifiablePresentation, true, false)

        Assertions.assertEquals(SignatureSuites.SIGNATURE_SUITE_RSASIGNATURE2018.term, ldSignature.type)
        Assertions.assertEquals(verificationMethod, ldSignature.verificationMethod)
        Assertions.assertEquals(created, ldSignature.created)
        Assertions.assertEquals(domain, ldSignature.domain)
        Assertions.assertEquals(nonce, ldSignature.nonce)
        Assertions.assertEquals(
            "eyJiNjQiOmZhbHNlLCJjcml0IjpbImI2NCJdLCJhbGciOiJSUzI1NiJ9..PexTQ753-C3IjZwC0F5yA-06EuiM_McqPBRcyPhHw0PdCaVdvK628kqG8PWABJ1oISU8Z75lzpfhwNwD2qRiPTLg6uQqbmm8p633hM0HCIih8Uf3QzflrUlxfPIiAdUmWZiNRHNPbm4KD4hvPl4S0kYmCLJEp0evMbazZHKgnKOzzGsvOIqpCwheH30uzbk5--z8XJGflMLEHqrp42DWuYB8y9l_yn830mC6xAzWe25KRSbODDk2xy1gjIcMeBYPkMuZ4MCamRUYsPuj-aLHq8q8iDrhUoUDH307v0OevDlyu6cG7_H0bgG6fGTzAT5EGkb-EhE3NfAvKo7nh3d6Mw",
            ldSignature.jws
        )

        Validation.validateJsonLd(verifiablePresentation)

        val verifier = RsaSignature2018LdVerifier(SignatureKeys.testRSAPublicKey)
        val verify = verifier.verify(verifiablePresentation)
        Assertions.assertTrue(verify)
    }
}