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

import id.walt.common.prettyPrint
import id.walt.crypto.KeyAlgorithm
import mu.KotlinLogging
import org.hyperledger.indy.sdk.crypto.Crypto
import org.junit.jupiter.api.Test
import org.nessus.didcomm.crypto.LibIndyService.closeAndDeleteWallet
import org.nessus.didcomm.crypto.LibIndyService.createAnOpenWallet
import org.nessus.didcomm.crypto.LibIndyService.createAndStoreDid
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.StorageType
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope
import org.nessus.didcomm.test.AbstractDidCommTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.Faber
import org.nessus.didcomm.test.NESSUS_OPTIONS_01
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.gson
import kotlin.test.assertEquals

/**
 * Start a local indy pool
 *
 * docker rm -f indy-pool
 * docker run --detach --name=indy-pool -p 9701-9708:9701-9708 indy-pool
 *
 * Remove dirty client state
 *
 * rm -rf ~/.indy_client
 */
class LibIndyTest: AbstractDidCommTest() {
    val log = KotlinLogging.logger {}

    @Test
    fun auth_crypt() {

        try {
            log.info("Create wallet - Faber")
            val faber = createAnOpenWallet(Faber.name)
            val faberDid = createAndStoreDid(faber, Faber.seed)
            log.info { "Faber Did: ${faberDid.qualified}" }

            log.info("Create wallet - Alice")
            val alice = createAnOpenWallet(Alice.name)
            val aliceDid = createAndStoreDid(alice, Alice.seed)
            log.info { "Alice Did: ${aliceDid.qualified}" }

            val msg = "Your hovercraft is full of eels."
            val encryptedMessage = Crypto.authCrypt(faber, faberDid.verkey, aliceDid.verkey, msg.toByteArray()).get()
            val authDecryptResult = Crypto.authDecrypt(alice, aliceDid.verkey, encryptedMessage).get()

            assertEquals(msg, String(authDecryptResult.decryptedMessage))
            assertEquals(faberDid.verkey, authDecryptResult.verkey)

        } finally {
            closeAndDeleteWallet(Alice.name)
            closeAndDeleteWallet(Faber.name)
        }
    }

    @Test
    fun packIndy_unpackIndy() {

        try {
            log.info("Create wallet - Faber")
            val faber = createAnOpenWallet(Faber.name)
            val faberDid = createAndStoreDid(faber, Faber.seed)
            log.info { "Faber Did: ${faberDid.qualified}" }

            log.info("Create wallet - Alice")
            val alice = createAnOpenWallet(Alice.name)
            val aliceDid = createAndStoreDid(alice, Alice.seed)
            log.info { "Alice Did: ${aliceDid.qualified}" }
            assertEquals("did:sov:RfoA7oboFMiFuJPEtPdvKP", aliceDid.qualified)

            val message = "Your hovercraft is full of eels."
            val receivers = gson.toJson(listOf(aliceDid.verkey))
            val packed = String(Crypto.packMessage(faber, receivers, faberDid.verkey, message.toByteArray()).get())
            log.info { "Packed: ${packed.prettyPrint()}"}

            val unpackedJson = String(Crypto.unpackMessage(alice, packed.toByteArray()).get())
            val unpacked = unpackedJson.decodeJson()
            log.info { "Unpacked: $unpacked"}
            assertEquals(message, unpacked["message"])
            assertEquals(aliceDid.verkey, unpacked["recipient_verkey"])
            assertEquals(faberDid.verkey, unpacked["sender_verkey"])

        } finally {
            closeAndDeleteWallet(Alice.name)
            closeAndDeleteWallet(Faber.name)
        }
    }

    @Test
    fun packIndy_unpackNessus() {

        try {
            log.info("Create wallet - Faber")
            val faber = createAnOpenWallet(Faber.name)
            val faberDid = createAndStoreDid(faber, Faber.seed)
            log.info { "Faber Did: ${faberDid.qualified}" }

            log.info("Create wallet - Alice")
            Wallet.Builder(Alice.name)
                .options(NESSUS_OPTIONS_01)
                .agentType(AgentType.NESSUS)
                .storageType(StorageType.IN_MEMORY)
                .build()
            val aliceDid = didService.createDid(DidMethod.SOV, KeyAlgorithm.EdDSA_Ed25519, Alice.seed.toByteArray())

            val message = "Your hovercraft is full of eels."
            val receivers = gson.toJson(listOf(aliceDid.verkey))
            val packed = String(Crypto.packMessage(faber, receivers, faberDid.verkey, message.toByteArray()).get())
            log.info { "Packed: ${packed.prettyPrint()}" }

            val unpacked = RFC0019EncryptionEnvelope()
                .unpackEncryptedEnvelope(packed)
            log.info { "Unpacked: $unpacked"}
            assertEquals(aliceDid.verkey, unpacked?.recipientVerkey)

        } finally {
            closeAndDeleteWallet(Faber.name)
            removeWallet(Alice.name)
        }
    }

    @Test
    fun packNessus_unpackIndy() {

        try {
            log.info("Create wallet - Faber")
            val faber = createAnOpenWallet(Faber.name)
            val faberDid = createAndStoreDid(faber, Faber.seed)
            log.info { "Faber Did: ${faberDid.qualified}" }

            log.info("Create wallet - Alice")
            Wallet.Builder(Alice.name)
                .options(NESSUS_OPTIONS_01)
                .agentType(AgentType.NESSUS)
                .storageType(StorageType.IN_MEMORY)
                .build()
            val aliceDid = didService.createDid(DidMethod.SOV, KeyAlgorithm.EdDSA_Ed25519, Alice.seed.toByteArray())

            val message = "Your hovercraft is full of eels."
            val packed = RFC0019EncryptionEnvelope()
                .packEncryptedEnvelope(message, aliceDid, faberDid)
            log.info { "Packed: ${packed.prettyPrint()}" }

            val unpackedJson = String(Crypto.unpackMessage(faber, packed.toByteArray()).get())
            val unpacked = unpackedJson.decodeJson()
            log.info { "Unpacked: $unpacked"}
            assertEquals(message, unpacked["message"])
            assertEquals(faberDid.verkey, unpacked["recipient_verkey"])
            assertEquals(aliceDid.verkey, unpacked["sender_verkey"])

        } finally {
            closeAndDeleteWallet(Faber.name)
            removeWallet(Alice.name)
        }
    }

}

