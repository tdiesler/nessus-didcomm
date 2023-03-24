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
import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.encodeBase58
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import mu.KotlinLogging
import org.didcommx.didcomm.common.VerificationMaterialFormat.JWK
import org.didcommx.didcomm.common.VerificationMethodType.ED25519_VERIFICATION_KEY_2018
import org.didcommx.didcomm.common.VerificationMethodType.JSON_WEB_KEY_2020
import org.didcommx.didcomm.common.VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.util.encodeHex

class SecretResolverServiceTest: AbstractAgentTest() {
    val log = KotlinLogging.logger {}

    @Test
    fun resolve_EdDSA_Ed25519_Private() {

        val aliceKeyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Alice.seed.toByteArray())
        val aliceDid = didService.createDid(DidMethod.KEY, keyAlias = aliceKeyId.id)
        aliceDid.uri shouldBe Alice.didkey

        val didDoc = didService.loadDidDoc(aliceDid.uri)
        val kid = didDoc.verificationMethods
            .first { it.type == ED25519_VERIFICATION_KEY_2018 }.id

        val secret = secretResolver.findKey(kid).get()
        log.info { secret.prettyPrint() }
        val verificationMaterial = secret.verificationMaterial
        secret.type shouldBe JSON_WEB_KEY_2020
        verificationMaterial.format shouldBe JWK

        val okp = OctetKeyPair.parse(verificationMaterial.value)
        "${okp.curve}" shouldBe "Ed25519"
        "${okp.algorithm}" shouldBe "EdDSA"
        okp.decodedX.encodeBase58() shouldBe Alice.verkey
        okp.decodedD.encodeHex() shouldBe Alice.seed.toByteArray().encodeHex()
    }

    @Test
    fun resolve_EdDSA_X25519_Private() {

        val aliceKeyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Alice.seed.toByteArray())
        val aliceDid = didService.createDid(DidMethod.KEY, keyAlias = aliceKeyId.id)
        aliceDid.uri shouldBe Alice.didkey

        val didDoc = didService.loadDidDoc(aliceDid.uri)
        val kid = didDoc.verificationMethods
            .first { it.type == X25519_KEY_AGREEMENT_KEY_2019 }.id

        val secret = secretResolver.findKey(kid).get()
        log.info { secret.prettyPrint() }
        val verificationMaterial = secret.verificationMaterial
        secret.type shouldBe JSON_WEB_KEY_2020
        verificationMaterial.format shouldBe JWK

        val okp = OctetKeyPair.parse(verificationMaterial.value)
        "${okp.curve}" shouldBe "X25519"
    }

    @Test
    fun resolve_EdDSA_Ed25519_Public() {

        val aliceKeyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Alice.seed.toByteArray())
        val aliceDid = didService.createDid(DidMethod.KEY, keyAlias = aliceKeyId.id)
        aliceDid.uri shouldBe Alice.didkey

        val didDocA = didService.loadDidDoc(aliceDid.uri)
        val kid = didDocA.verificationMethods
            .first { it.type == ED25519_VERIFICATION_KEY_2018 }.id

        secretResolver.findKey(kid).isPresent shouldBe true

        // Delete the key from the store
        keyStore.getKeyId(aliceDid.verkey)?.also { keyStore.delete(it) }
        secretResolver.findKey(kid).isPresent shouldBe false

        didService.importDid(aliceDid)

        val key = keyStore.load(aliceDid.verkey)
        key.keyPair!!.public shouldNotBe null
        key.keyPair!!.private shouldBe null

        secretResolver.findKey(kid).isPresent shouldBe false
    }
}
