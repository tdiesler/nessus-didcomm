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
package org.nessus.didcomm.test.model

import id.walt.crypto.KeyAlgorithm
import id.walt.services.keystore.KeyType
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.didcommx.didcomm.common.VerificationMethodType.ED25519_VERIFICATION_KEY_2018
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.StorageType
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice

class WalletTest: AbstractAgentTest() {

    @Test
    fun createWalletWithDidKey() {

        val alice = Wallet.Builder(Alice.name)
            .build()

        alice.name shouldBe Alice.name
        alice.agentType shouldBe AgentType.NESSUS
        alice.storageType shouldBe StorageType.IN_MEMORY

        val keyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Alice.seed.toByteArray())
        val aliceDid = alice.createDid(DidMethod.KEY, keyId.id)

        aliceDid.uri shouldBe Alice.didkey
        aliceDid.verkey shouldBe Alice.verkey

        // Verify keys in KeyStore
        keyStore.load(aliceDid.uri, KeyType.PRIVATE) shouldNotBe null
        keyStore.load(aliceDid.verkey, KeyType.PRIVATE) shouldNotBe null

        // Verify Did in DidService
        val loadedDid = didService.loadDid(aliceDid.uri)
        loadedDid shouldBe aliceDid

        // Verify DidDoc in DidService
        val didDoc = didService.loadDidDoc(aliceDid.uri)
        val ed25519Method = didDoc.findVerificationMethod { it.type == ED25519_VERIFICATION_KEY_2018 }
        ed25519Method?.controller shouldBe aliceDid.uri

        walletService.removeWallet(alice.id)

        didService.hasDid(aliceDid.uri) shouldBe false
        keyStore.getKeyId(aliceDid.uri) shouldBe null
    }
}
