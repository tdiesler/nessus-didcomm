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
import org.junit.jupiter.api.Test
import org.nessus.didcomm.did.DidService.createDid
import org.nessus.didcomm.test.AbstractDidcommTest
import org.nessus.didcomm.wallet.DidMethod
import org.web3j.utils.Numeric
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
        log.info { "pkRaw: ${Numeric.toHexString(pkRaw)}" }

        // Build PublicKey from pubkey raw bytes
        // Then verify that we can get the raw bytes from the X.509 encoded PublicKey
        val pubKey: PublicKey = buildEd25519PubKey(encBase64(pkRaw))
        assertEquals("X.509", pubKey.format)
        val pubKeyX509 = pubKey.encoded
        log.info { "pk509: ${Numeric.toHexString(pubKeyX509)}" }

        // We assume/verify that the last 32 bytes are equal to the pubkey raw bytes
        val pubKeyRaw = pubKeyX509.sliceArray(pubKeyX509.size - 32 until pubKeyX509.size)
        log.info { "pkRaw: ${Numeric.toHexString(pubKeyRaw)}" }
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
        val did = createDid(DidMethod.KEY, seed=seedBytes).did
        assertEquals("did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp", did.qualified)
    }

    @Test
    fun test_DidKey_Trustee1() {

        val seed = "000000000000000000000000Trustee1"
        val seedBytes = seed.toByteArray(Charsets.UTF_8)

        val didInfo = createDid(DidMethod.KEY, seed=seedBytes)
        checkNotNull(didInfo.pubKey)
        checkNotNull(didInfo.prvKey)

        val pubKey = didInfo.pubKey
        val prvKey = didInfo.prvKey
        val did = didInfo.did
        log.info { did.qualified }
        log.info { "seed:      $seed" }
        log.info { "verkey58:  $seed" }
        log.info { "verkeyHex: $seed" }
        log.info { "seedHex:   $seed" }
        log.info { "secretHex: $seed" }
        assertEquals("did:key:z6MkukGVb3mRvTu1msArDKY9UwxeZFGjmwnCKtdQttr4Fk6i", did.qualified)
    }
}
