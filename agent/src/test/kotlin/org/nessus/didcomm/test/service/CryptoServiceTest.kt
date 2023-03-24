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

import com.goterl.lazysodium.interfaces.Sign
import com.goterl.lazysodium.utils.KeyPair
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import id.walt.crypto.Key
import id.walt.crypto.KeyAlgorithm
import id.walt.services.CryptoProvider
import id.walt.services.key.Keys
import id.walt.services.keystore.KeyType
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.nessus.didcomm.service.LazySodiumService
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.service.toOctetKeyPair
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.util.decodeHex
import org.nessus.didcomm.util.encodeBase64Url
import org.nessus.didcomm.util.encodeHex
import org.nessus.didcomm.util.encodeJson

class CryptoServiceTest: AbstractAgentTest() {
    val log = KotlinLogging.logger {}

    @Test
    fun signVerifySeedMessage() {

        val keyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Alice.seedHex.decodeHex())

        val data = "Hello".toByteArray()
        val signature = cryptoService.sign(keyId, data)
        cryptoService.verify(keyId, signature, data) shouldBe true
    }

    @Test
    fun test_OKP_Ed25519_X25519() {

        val seedBytes = "0000000000000000000000000000000000000000000000000000000000000005".decodeHex()
        val keyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, seedBytes)
        val didKey05 = didService.createDid(DidMethod.KEY, keyAlias = keyId.id)
        didKey05.uri shouldBe "did:key:z6MkwYMhwTvsq376YBAcJHy3vyRWzBgn5vKfVqqDCgm7XVKU"

        // Test OKP Ed25519
        run {

            // Load the key associated with the DID and get the OKP representation of it
            val key: Key = keyStore.load(didKey05.uri, KeyType.PRIVATE)
            val octetKeyPair: OctetKeyPair = key.toOctetKeyPair()
            log.info { octetKeyPair.toJSONObject().encodeJson(true) }

            key.cryptoProvider shouldBe CryptoProvider.SUN
            key.algorithm shouldBe KeyAlgorithm.EdDSA_Ed25519
            octetKeyPair.curve.name shouldBe "Ed25519"

            // Get the public/private key bytes
            val keys = Keys(key.keyId.id, key.keyPair!!, "SunEC")
            val ed25519PubBytes = keys.getPubKey()
            val ed25519PrvBytes = keys.getPrivKey()
            log.info { "ed25519PubBytes: ${ed25519PubBytes.encodeHex()}" }
            log.info { "ed25519PrvBytes: ${ed25519PrvBytes.encodeHex()}" }

            val x = ed25519PubBytes.encodeBase64Url()
            val d = ed25519PrvBytes.encodeBase64Url()
            log.info { "x: $x" }
            log.info { "d: $d" }

            // Assert that we curve coordinates match
            x shouldBe "${octetKeyPair.x}"
            d shouldBe "${octetKeyPair.d}"
            x shouldBe "_eT7oDCtAC98L31MMx9J0T-w7HR-zuvsY08f9MvKne8"
            d shouldBe "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU"
        }

        // Test OKP X25519
        run {
            // Load the key associated with the DID and get the OKP representation of it
            val key: Key = keyStore.load(didKey05.uri, KeyType.PRIVATE)

            key.cryptoProvider shouldBe CryptoProvider.SUN
            key.algorithm shouldBe KeyAlgorithm.EdDSA_Ed25519

            // Get the public/private key bytes
            val keys = Keys(key.keyId.id, key.keyPair!!, "SunEC")
            val ed25519PubBytes = keys.getPubKey()
            val ed25519PrvBytes = keys.getPrivKey()
            log.info { "ed25519PubBytes: ${ed25519PubBytes.encodeHex()}" }
            log.info { "ed25519PrvBytes: ${ed25519PrvBytes.encodeHex()}" }

            val ed25519KeyPair = KeyPair(
                com.goterl.lazysodium.utils.Key.fromBytes(ed25519PubBytes),
                com.goterl.lazysodium.utils.Key.fromBytes(ed25519PrvBytes))

            val lazySign = LazySodiumService.lazySodium as Sign.Lazy
            val x25519KeyPair = lazySign.convertKeyPairEd25519ToCurve25519(ed25519KeyPair)
            val x25519PubBytes = x25519KeyPair.publicKey.asBytes
            val x25519PrvBytes = x25519KeyPair.secretKey.asBytes

            log.info { "x25519PubBytes: ${x25519PubBytes.encodeHex()}" }
            log.info { "x25519PrvBytes: ${x25519PrvBytes.encodeHex()}" }

            val x = x25519PubBytes.encodeBase64Url()
            val d = x25519PrvBytes.encodeBase64Url()
            log.info { "x: $x" }
            log.info { "d: $d" }

            // Assert that we curve coordinates match
            x shouldBe "jRIz3oriXDNZmnb35XQb7K1UIlz3ae1ao1YSqLeBXHs"
            d shouldBe "aEAAB3VBFPCQtgF3N__wRiXhMOgeiRGstpPC3gnJ1Eo"
        }

        // Do the above through the DidService
        run {

            val ed25519Prv = cryptoService.toOctetKeyPair(didKey05.verkey, Curve.Ed25519, KeyType.PRIVATE)
            "${ed25519Prv.x}" shouldBe "_eT7oDCtAC98L31MMx9J0T-w7HR-zuvsY08f9MvKne8"
            "${ed25519Prv.d}" shouldBe "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU"

            val x25519Prv = cryptoService.toOctetKeyPair(didKey05.verkey, Curve.X25519, KeyType.PRIVATE)
            "${x25519Prv.x}" shouldBe "jRIz3oriXDNZmnb35XQb7K1UIlz3ae1ao1YSqLeBXHs"
            "${x25519Prv.d}" shouldBe "aEAAB3VBFPCQtgF3N__wRiXhMOgeiRGstpPC3gnJ1Eo"

            val ed25519Pub = cryptoService.toOctetKeyPair(didKey05.verkey, Curve.Ed25519)
            "${ed25519Pub.x}" shouldBe "_eT7oDCtAC98L31MMx9J0T-w7HR-zuvsY08f9MvKne8"
            ed25519Pub.d shouldBe null

            val x25519Pub = cryptoService.toOctetKeyPair(didKey05.verkey, Curve.X25519)
            "${x25519Pub.x}" shouldBe "jRIz3oriXDNZmnb35XQb7K1UIlz3ae1ao1YSqLeBXHs"
            x25519Pub.d shouldBe null
        }
    }

}
