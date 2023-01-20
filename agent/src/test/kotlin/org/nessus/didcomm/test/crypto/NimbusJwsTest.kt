/*-
 * #%L
 * Nessus DIDComm :: Core
 * %%
 * Copyright (C) 2022 Nessus
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package org.nessus.didcomm.test.crypto

import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.JWSObject
import com.nimbusds.jose.JWSSigner
import com.nimbusds.jose.JWSVerifier
import com.nimbusds.jose.Payload
import com.nimbusds.jose.crypto.Ed25519Signer
import com.nimbusds.jose.crypto.Ed25519Verifier
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import com.nimbusds.jose.jwk.gen.OctetKeyPairGenerator
import org.junit.jupiter.api.Test
import org.nessus.didcomm.test.AbstractDidCommTest
import org.nessus.didcomm.util.encodeJsonPretty
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Nimbus JOSE + JWT
 * https://connect2id.com/products/nimbus-jose-jwt
 */
class NimbusJwsTest: AbstractDidCommTest() {

    /**
     * JSON Web Signature (JWS) with Edwards-Curve Digital Signature Algorithm / Ed25519
     */
    @Test
    fun jws_EdDSA_Ed25519() {

        // Generate a key pair with Ed25519 curve
        val jwk: OctetKeyPair = OctetKeyPairGenerator(Curve.Ed25519)
            .keyID("123")
            .generate()

        log.info { jwk.toJSONObject().encodeJsonPretty() }

        // Create the EdDSA signer
        val signer: JWSSigner = Ed25519Signer(jwk)

        // Creates the JWS object with payload
        val jwsObject = JWSObject(
            JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID(jwk.keyID).build(),
            Payload("We are having a crypto party!")
        )

        // Compute the EdDSA signature
        jwsObject.sign(signer)

        // Serialize the JWS to compact form
        val s: String = jwsObject.serialize()

        // The recipient creates a verifier with the public EdDSA key
        val verifier: JWSVerifier = Ed25519Verifier(jwk.toPublicJWK())

        // Verify the EdDSA signature

        // Verify the EdDSA signature
        assertTrue(jwsObject.verify(verifier), "Ed25519 signature verified")
        assertEquals(jwsObject.payload.toString(), "We are having a crypto party!")
    }
}
