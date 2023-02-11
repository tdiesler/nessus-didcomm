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
package org.nessus.didcomm.test.service

import com.nimbusds.jose.jwk.OctetKeyPair
import id.walt.common.prettyPrint
import id.walt.crypto.KeyId
import mu.KotlinLogging
import org.didcommx.didcomm.common.VerificationMaterialFormat.JWK
import org.didcommx.didcomm.common.VerificationMethodType.JSON_WEB_KEY_2020
import org.didcommx.didcomm.secret.Secret
import org.junit.jupiter.api.Test
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.test.AbstractDidCommTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.util.encodeBase58
import org.nessus.didcomm.util.encodeHex
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull

class SecretResolverServiceTest: AbstractDidCommTest() {
    val log = KotlinLogging.logger {}

    @Test
    fun resolve_EdDSA_Ed25519_Private() {

        val aliceDid = didService.createDid(DidMethod.KEY, seed= Alice.seed.toByteArray())
        assertEquals(Alice.didkey, aliceDid.qualified)

        val secret: Secret = secretResolver.findKey(aliceDid.verkey).get()
        log.info { secret.prettyPrint() }
        val verificationMaterial = secret.verificationMaterial
        assertEquals(JSON_WEB_KEY_2020, secret.type)
        assertEquals(JWK, verificationMaterial.format)

        val okp = OctetKeyPair.parse(verificationMaterial.value)
        assertEquals("Ed25519", "${okp.curve}")
        assertEquals("EdDSA", "${okp.algorithm}")
        assertEquals(Alice.verkey, okp.decodedX.encodeBase58())
        assertEquals(Alice.seed.toByteArray().encodeHex(), okp.decodedD.encodeHex())
    }

    @Test
    fun resolve_EdDSA_X25519_Private() {

        val aliceDid = didService.createDid(DidMethod.KEY, seed= Alice.seed.toByteArray())
        assertEquals(Alice.didkey, aliceDid.qualified)

        val kidX25519 = "${aliceDid.qualified}#key-x25519-1"
        val keyId = KeyId(keyStore.getKeyId(aliceDid.qualified)!!)
        keyStore.addAlias(keyId, kidX25519)

        val secret: Secret = secretResolver.findKey(kidX25519).get()
        log.info { secret.prettyPrint() }
        val verificationMaterial = secret.verificationMaterial
        assertEquals(JSON_WEB_KEY_2020, secret.type)
        assertEquals(JWK, verificationMaterial.format)

        val okp = OctetKeyPair.parse(verificationMaterial.value)
        assertEquals("X25519", "${okp.curve}")
    }

    @Test
    fun resolve_EdDSA_Ed25519_Public() {

        val aliceDid = didService.createDid(DidMethod.KEY, seed= Alice.seed.toByteArray())
        assertEquals(Alice.didkey, aliceDid.qualified)

        // Delete the key from the store
        keyStore.getKeyId(aliceDid.verkey)?.also { keyStore.delete(it) }
        assertFalse(secretResolver.findKey(aliceDid.verkey).isPresent)

        didService.registerWithKeyStore(aliceDid)
        val key = keyStore.load(aliceDid.verkey)
        assertNotNull(key.keyPair!!.public)
        assertNull(key.keyPair!!.private)

        assertFalse(secretResolver.findKey(aliceDid.verkey).isPresent)
    }
}
