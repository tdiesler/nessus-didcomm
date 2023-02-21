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

import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.buildEd25519PubKey
import id.walt.crypto.convertRawKeyToMultiBase58Btc
import id.walt.crypto.decodeBase58
import id.walt.crypto.encBase64
import id.walt.crypto.getMulticodecKeyCode
import id.walt.services.keystore.KeyType
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.Faber
import org.nessus.didcomm.util.encodeHex
import java.security.PublicKey

/**
 * Ed25519 Online Tool - Sign or Verify
 * https://cyphr.me/ed25519_tool/ed.html
 *
 * did:key test vectors
 * https://w3c-ccg.github.io/did-method-key/#test-vectors
 * https://github.com/w3c-ccg/did-method-key/tree/main/test-vectors
 */
class DidServiceTest: AbstractAgentTest() {
    val log = KotlinLogging.logger {}

    @Test
    fun test_RawPubKey_to_DidKey() {

        // ed25519-x25519.json
        // did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp

        val pkRaw = "4zvwRjXUKGfvwnParsHAS3HuSVzV5cA4McphgmoCtajS".decodeBase58()
        log.info { "pkRaw: ${pkRaw.encodeHex()}" }

        // Build PublicKey from pubkey raw bytes
        // Then verify that we can get the raw bytes from the X.509 encoded PublicKey
        val pubKey: PublicKey = buildEd25519PubKey(encBase64(pkRaw))
        pubKey.format shouldBe "X.509"
        val pubKeyX509 = pubKey.encoded
        log.info { "pk509: ${pubKeyX509.encodeHex()}" }

        // We assume/verify that the last 32 bytes are equal to the pubkey raw bytes
        val pubKeyRaw = pubKeyX509.sliceArray(pubKeyX509.size - 32 until pubKeyX509.size)
        log.info { "pkRaw: ${pubKeyRaw.encodeHex()}" }
        pkRaw.contentEquals(pubKeyRaw) shouldBe true

        // Construct did from the 32 pubkey raw bytes
        val keyAlgorithm = KeyAlgorithm.EdDSA_Ed25519
        check(pubKeyRaw.size == 32) { "Expect 32 pubkey bytes" }
        val did = convertRawKeyToMultiBase58Btc(pubKeyRaw, getMulticodecKeyCode(keyAlgorithm))
        "did:key:$did" shouldBe "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
    }

    @Test
    fun test_DidKey_Seed00() {
        val seedBytes = ByteArray(32)
        val keyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, seedBytes)
        val did = didService.createDid(DidMethod.KEY, keyId.id)
        did.uri shouldBe "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
    }

    @Test
    fun test_Did_Fixture() {

        val faberKeyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Faber.seed.toByteArray())
        val faberDid = didService.createDid(DidMethod.KEY, faberKeyId.id)
        val faberKey = keyStore.load(faberDid.uri, KeyType.PRIVATE)

        val pubKey = faberKey.keyPair?.public
        val prvKey = faberKey.keyPair?.private
        val pubkeyBytes = pubKey?.encoded
        val prvkeyBytes = prvKey?.encoded
        val verkey58 = faberDid.verkey
        val verkeyBytes = verkey58.decodeBase58()
        log.info { faberDid.uri }
        log.info { "seed:      ${Faber.seed}" }
        log.info { "verkey58:  ${faberDid.verkey}" }
        log.info { "verkeyHex: ${verkeyBytes.encodeHex()}" }
        log.info { "seedHex:   ${Faber.seed.toByteArray().encodeHex()}" }
        log.info { "pubkeyHex: ${pubKey?.format} ${pubkeyBytes?.encodeHex()}" }
        log.info { "prvkeyHex: ${prvKey?.format} ${prvkeyBytes?.encodeHex()}" }
        faberDid.verkey shouldBe Faber.verkey
        faberDid.uri shouldBe Faber.didkey

        val faberSov = didService.createDid(DidMethod.SOV, faberKeyId.id)
        faberSov.verkey shouldBe Faber.verkey
        faberSov.uri shouldBe Faber.didsov

        // Alice -------------------------------------------------------------------------------------------------------

        val aliceKeyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Alice.seed.toByteArray())
        val aliceDid = didService.createDid(DidMethod.KEY, aliceKeyId.id)
        aliceDid.verkey shouldBe Alice.verkey
        aliceDid.uri shouldBe Alice.didkey

        val aliceSov = didService.createDid(DidMethod.SOV, aliceKeyId.id)
        aliceSov.verkey shouldBe Alice.verkey
        aliceSov.uri shouldBe Alice.didsov
    }
}
