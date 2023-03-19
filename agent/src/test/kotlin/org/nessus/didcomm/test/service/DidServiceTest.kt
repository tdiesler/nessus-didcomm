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
import id.walt.crypto.decodeBase58
import id.walt.services.keystore.KeyType
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import io.kotest.matchers.string.shouldStartWith
import mu.KotlinLogging
import org.nessus.didcomm.did.DidDocV2
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.DidCreateOptions
import org.nessus.didcomm.service.DidPeerOptions
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.Faber
import org.nessus.didcomm.util.encodeHex

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
    fun testDidFixture() {

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

    @Test
    fun testDidKeySeed00() {
        val seedBytes = ByteArray(32)
        val keyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, seedBytes)
        val did = didService.createDid(DidMethod.KEY, keyId.id)
        did.uri shouldBe "did:key:z6MkiTBz1ymuepAQ4HEHYSF1H8quG5GLVVQR3djdX3mDooWp"
    }

    @Test
    fun testDidKey() {
        testDidMethod(DidMethod.KEY, null)
    }

    @Test
    fun testDidPeerNumAlgo0() {
        testDidMethod(DidMethod.PEER, DidPeerOptions(numalgo = 0))
    }

    @Test
    fun testDidPeerNumAlgo2() {
        testDidMethod(DidMethod.PEER, DidPeerOptions(numalgo = 2))
    }

    @Test
    fun testDidSov() {
        testDidMethod(DidMethod.SOV, null)
    }

    private fun testDidMethod(method: DidMethod, options: DidCreateOptions?) {

        val alice = Wallet.Builder(Alice.name).build()

        try {
            val keyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Alice.seed.toByteArray())

            val did = alice.createDid(method, keyId.id, options)
            did.verkey shouldBe Alice.verkey

            val numalgo = (options as? DidPeerOptions)?.numalgo

            when (method) {
                DidMethod.KEY -> did.uri shouldBe Alice.didkey
                DidMethod.PEER -> when (numalgo) {
                    0 -> did.uri shouldBe Alice.didpeer0
                    2 -> did.uri shouldStartWith "did:peer:2"
                    else -> throw IllegalStateException("Unknown numalgo: $numalgo")
                }

                DidMethod.SOV -> did.uri shouldBe Alice.didsov
            }

            val key = keyStore.load(did.uri, KeyType.PUBLIC)
            key shouldNotBe null

            val loadedDid = didService.loadDid(did.uri)
            loadedDid shouldBe did

            var didDoc = didService.loadDidDocument(did.uri)
            didDoc.serviceEndpoint() shouldNotBe null

            didService.deleteDid(did)

            didService.hasDid(did.uri) shouldBe false
            keyStore.getKeyId(did.uri) shouldBe null

            // We can resolve the Did Document when we have the public key
            if (method == DidMethod.SOV) {
                keyStore.store(key)
                keyStore.addAlias(key.keyId, did.uri)
            }

            didDoc = didService.resolveDidDocument(did.uri) as DidDocV2
            log.info { "Resolved DidDocument: ${didDoc.encodeJson(true)}" }

            val resolvedDid = didService.resolveDid(did.uri)
            resolvedDid shouldBe did

            // Resolving a Did/Document does NOT add it to the store
            didService.hasDid(did.uri) shouldBe false

            // Delete the public key
            keyStore.delete(keyId.id)

            didService.importDid(did) shouldNotBe null

            didService.loadDid(did.uri) shouldBe did

            didDoc = didService.loadDidDocument(did.uri)
            didDoc.serviceEndpoint() shouldNotBe null

            alice.removeDid(did)
        } finally {
            removeWallet(alice)
        }
    }
}
