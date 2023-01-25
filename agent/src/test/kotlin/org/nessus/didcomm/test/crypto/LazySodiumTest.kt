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

import com.goterl.lazysodium.interfaces.AEAD
import com.goterl.lazysodium.interfaces.Box
import com.goterl.lazysodium.utils.Key
import com.goterl.lazysodium.utils.KeyPair
import id.walt.crypto.KeyAlgorithm
import id.walt.services.keystore.KeyType
import mu.KotlinLogging
import org.junit.jupiter.api.Test
import org.nessus.didcomm.crypto.LazySodiumService.convertEd25519toCurve25519
import org.nessus.didcomm.crypto.LazySodiumService.cryptoBoxEasyBytes
import org.nessus.didcomm.crypto.LazySodiumService.cryptoBoxOpenEasyBytes
import org.nessus.didcomm.crypto.LazySodiumService.lazySodium
import org.nessus.didcomm.test.AbstractDidCommTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.Faber
import org.nessus.didcomm.util.decodeHex
import org.nessus.didcomm.util.encodeHex
import kotlin.test.assertEquals

class LazySodiumTest: AbstractDidCommTest() {
    val log = KotlinLogging.logger {}

    @Test
    fun lazyBoxEasy() {

        val faberKeyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Faber.seed.toByteArray())
        val faberKeys = keyStore.load(faberKeyId.id, KeyType.PRIVATE).keyPair!!.convertEd25519toCurve25519()

        val aliceKeyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Alice.seed.toByteArray())
        val aliceKeys = keyStore.load(aliceKeyId.id, KeyType.PRIVATE).keyPair!!.convertEd25519toCurve25519()

        val boxLazy = lazySodium as Box.Lazy
        val nonce = lazySodium.nonce(Box.NONCEBYTES)
        val encryptKeys = KeyPair(aliceKeys.publicKey, faberKeys.secretKey)
        val decryptKeys = KeyPair(faberKeys.publicKey, aliceKeys.secretKey)
        val cipherText = boxLazy.cryptoBoxEasy("Scheena Dog", nonce, encryptKeys)
        val message = boxLazy.cryptoBoxOpenEasy(cipherText, nonce, decryptKeys)
        assertEquals("Scheena Dog", message)
    }

    @Test
    fun lazyBoxEasyBytes() {

        val faberKeyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Faber.seed.toByteArray())
        val faberKeys = keyStore.load(faberKeyId.id, KeyType.PRIVATE).keyPair!!.convertEd25519toCurve25519()

        val aliceKeyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Alice.seed.toByteArray())
        val aliceKeys = keyStore.load(aliceKeyId.id, KeyType.PRIVATE).keyPair!!.convertEd25519toCurve25519()

        val aeadLazy = lazySodium as AEAD.Lazy
        val aeadMethod = AEAD.Method.XCHACHA20_POLY1305_IETF
        val cek: Key = aeadLazy.keygen(aeadMethod)
        log.info { "cek: ${cek.asBytes.size} ${cek.asHexString}" }

        val boxLazy = lazySodium as Box.Lazy
        val nonce = lazySodium.nonce(Box.NONCEBYTES)
        val encryptKeys = KeyPair(aliceKeys.publicKey, faberKeys.secretKey)
        val decryptKeys = KeyPair(faberKeys.publicKey, aliceKeys.secretKey)

        val messageLen = AEAD.XCHACHA20POLY1305_IETF_KEYBYTES
        val cipherTextLazy = boxLazy.cryptoBoxEasyBytes(cek.asBytes, nonce, encryptKeys)
        val message = boxLazy.cryptoBoxOpenEasyBytes(cipherTextLazy.decodeHex(), messageLen, nonce, decryptKeys)
        assertEquals(cek.asBytes.encodeHex(), message)
    }

    @Test
    fun lazyBoxSealEasy() {

        val aliceKeyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Alice.seed.toByteArray())
        val aliceKeys = keyStore.load(aliceKeyId.id, KeyType.PRIVATE).keyPair!!
        val aliceCurve25519Keys = aliceKeys.convertEd25519toCurve25519()

        val boxLazy = lazySodium as Box.Lazy
        val cipherText = boxLazy.cryptoBoxSealEasy("Scheena Dog", aliceCurve25519Keys.publicKey)
        val message = boxLazy.cryptoBoxSealOpenEasy(cipherText, aliceCurve25519Keys)
        assertEquals("Scheena Dog", message)
    }

    @Test
    fun lazyAEAD() {

        val aeadLazy = lazySodium as AEAD.Lazy
        val aeadMethod = AEAD.Method.XCHACHA20_POLY1305_IETF
        val cek: Key = aeadLazy.keygen(aeadMethod)

        val nonce = lazySodium.nonce(Box.NONCEBYTES)
        val ciphertext = aeadLazy.encryptDetached("Scheena Dog", null, null, nonce, cek, aeadMethod)
        val decrypted = aeadLazy.decryptDetached(ciphertext, null, null, nonce, cek, aeadMethod)
        assertEquals("Scheena Dog", decrypted.message.decodeToString())
    }
}

