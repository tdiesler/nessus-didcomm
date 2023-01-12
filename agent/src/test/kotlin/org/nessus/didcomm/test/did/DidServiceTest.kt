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
package org.nessus.didcomm.test.did

import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.buildEd25519PubKey
import id.walt.crypto.convertRawKeyToMultiBase58Btc
import id.walt.crypto.decodeBase58
import id.walt.crypto.encBase64
import id.walt.crypto.getMulticodecKeyCode
import id.walt.services.keystore.KeyStoreService
import id.walt.services.keystore.KeyType
import org.junit.jupiter.api.Test
import org.nessus.didcomm.test.AbstractDidcommTest
import org.nessus.didcomm.test.Faber
import org.nessus.didcomm.util.encodeHex
import org.nessus.didcomm.wallet.DidMethod
import java.security.PublicKey
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Ed25519 Online Tool - Sign or Verify
 * https://cyphr.me/ed25519_tool/ed.html
 */
class DidServiceTest: AbstractDidcommTest() {

    @Test
    fun test_RawPubKey_to_DidKey() {

        // ed25519-x25519.json
        val pkRaw = "4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS".decodeBase58()
        log.info { "pkRaw: ${pkRaw.encodeHex()}" }

        // Build PublicKey from pubkey raw bytes
        // Then verify that we can get the raw bytes from the X.509 encoded PublicKey
        val pubKey: PublicKey = buildEd25519PubKey(encBase64(pkRaw))
        assertEquals("X.509", pubKey.format)
        val pubKeyX509 = pubKey.encoded
        log.info { "pk509: ${pubKeyX509.encodeHex()}" }

        // We assume/verify that the last 32 bytes are equal to the pubkey raw bytes
        val pubKeyRaw = pubKeyX509.sliceArray(pubKeyX509.size - 32 until pubKeyX509.size)
        log.info { "pkRaw: ${pubKeyRaw.encodeHex()}" }
        assertTrue(pkRaw.contentEquals(pubKeyRaw))

        // Construct did from the 32 pubkey raw bytes
        val keyAlgorithm = KeyAlgorithm.EdDSA_Ed25519
        check(pubKeyRaw.size == 32) { "Expect 32 pubkey bytes" }
        val did = convertRawKeyToMultiBase58Btc(pubKeyRaw, getMulticodecKeyCode(keyAlgorithm))
        assertEquals("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp", "did:key:$did")
    }

    @Test
    fun test_DidKey_Seed00() {
        val seedBytes = ByteArray(32)
        val did = didService.createDid(DidMethod.KEY, seed=seedBytes)
        assertEquals("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp", did.qualified)
    }

    @Test
    fun test_DidKey_Trustee1() {

        val seed = Faber.seed
        val seedBytes = seed.toByteArray(Charsets.UTF_8)

        val did = didService.createDid(DidMethod.KEY, seed=seedBytes)
        val keyStore = KeyStoreService.getService()
        val key = keyStore.load(did.qualified, KeyType.PRIVATE)

        val pubKey = key.keyPair?.public
        val prvKey = key.keyPair?.private
        val pubkeyBytes = pubKey?.encoded
        val prvkeyBytes = prvKey?.encoded
        val verkey58 = did.verkey as String
        val verkeyBytes = verkey58.decodeBase58()
        log.info { did.qualified }
        log.info { "seed:      $seed" }
        log.info { "verkey58:  ${did.verkey}" }
        log.info { "verkeyHex: ${verkeyBytes.encodeHex()}" }
        log.info { "seedHex:   ${seedBytes.encodeHex()}" }
        log.info { "pubkeyHex: ${pubKey?.format} ${pubkeyBytes?.encodeHex()}" }
        log.info { "prvkeyHex: ${prvKey?.format} ${prvkeyBytes?.encodeHex()}" }
        assertEquals(Faber.didkey, did.qualified)
        assertEquals(Faber.verkey, did.verkey)
    }
}
