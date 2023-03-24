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
package org.nessus.didcomm.itest

import id.walt.common.prettyPrint
import io.kotest.core.annotation.EnabledIf
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.hyperledger.indy.sdk.crypto.Crypto
import org.nessus.didcomm.service.LibIndyService.closeAndDeleteWallet
import org.nessus.didcomm.service.LibIndyService.createAnOpenWallet
import org.nessus.didcomm.service.LibIndyService.createAndStoreDid
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.EncryptionEnvelopeV1
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.gson

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
@EnabledIf(AcaPyOnlyCondition::class)
class LibIndyTest: AbstractIntegrationTest() {
    private val log = KotlinLogging.logger {}

    @Test
    fun auth_crypt() {

        try {
            log.info("Create wallet - Faber")
            val faber = createAnOpenWallet(Faber.name)
            val faberDid = createAndStoreDid(faber, Faber.seed)
            log.info { "Faber Did: ${faberDid.uri}" }

            log.info("Create wallet - Alice")
            val alice = createAnOpenWallet(Alice.name)
            val aliceDid = createAndStoreDid(alice, Alice.seed)
            log.info { "Alice Did: ${aliceDid.uri}" }

            val msg = "Your hovercraft is full of eels."
            val encryptedMessage = Crypto.authCrypt(faber, faberDid.verkey, aliceDid.verkey, msg.toByteArray()).get()
            val authDecryptResult = Crypto.authDecrypt(alice, aliceDid.verkey, encryptedMessage).get()

            String(authDecryptResult.decryptedMessage) shouldBe msg
            authDecryptResult.verkey shouldBe faberDid.verkey

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
            log.info { "Faber Did: ${faberDid.uri}" }

            log.info("Create wallet - Alice")
            val alice = createAnOpenWallet(Alice.name)
            val aliceDid = createAndStoreDid(alice, Alice.seed)
            log.info { "Alice Did: ${aliceDid.uri}" }
            aliceDid.uri shouldBe "did:sov:RfoA7oboFMiFuJPEtPdvKP"

            val message = "Your hovercraft is full of eels."
            val receivers = gson.toJson(listOf(aliceDid.verkey))
            val packed = String(Crypto.packMessage(faber, receivers, faberDid.verkey, message.toByteArray()).get())
            log.info { "Packed: ${packed.prettyPrint()}"}

            val unpackedJson = String(Crypto.unpackMessage(alice, packed.toByteArray()).get())
            val unpacked = unpackedJson.decodeJson()
            log.info { "Unpacked: $unpacked"}
            unpacked["message"] shouldBe message
            unpacked["recipient_verkey"] shouldBe aliceDid.verkey
            unpacked["sender_verkey"] shouldBe faberDid.verkey

        } finally {
            closeAndDeleteWallet(Alice.name)
            closeAndDeleteWallet(Faber.name)
        }
    }

    @Test
    fun packIndy_unpackNessus() {

        log.info("Create wallet - Alice")
        val alice = Wallet.Builder(Alice.name).build()

        try {
            log.info("Create wallet - Faber")
            val faber = createAnOpenWallet(Faber.name)
            val faberDid = createAndStoreDid(faber, Faber.seed)
            log.info { "Faber Did: ${faberDid.uri}" }

            val aliceDid = alice.createDid(DidMethod.SOV)

            val message = "Your hovercraft is full of eels."
            val receivers = gson.toJson(listOf(aliceDid.verkey))
            val packed = String(Crypto.packMessage(faber, receivers, faberDid.verkey, message.toByteArray()).get())
            log.info { "Packed: ${packed.prettyPrint()}" }

            val unpacked = EncryptionEnvelopeV1()
                .unpackEncryptedEnvelope(packed)
            log.info { "Unpacked: $unpacked"}
            unpacked?.recipientVerkey shouldBe aliceDid.verkey

        } finally {
            closeAndDeleteWallet(Faber.name)
            removeWallet(alice)
        }
    }

    @Test
    fun packNessus_unpackIndy() {

        log.info("Create wallet - Alice")
        val alice = Wallet.Builder(Alice.name).build()

        try {
            log.info("Create wallet - Faber")
            val faber = createAnOpenWallet(Faber.name)
            val faberDid = createAndStoreDid(faber, Faber.seed)
            log.info { "Faber Did: ${faberDid.uri}" }

            log.info("Create wallet - Alice")
            val aliceDid = alice.createDid(DidMethod.SOV)

            val message = "Your hovercraft is full of eels."
            val packed = EncryptionEnvelopeV1()
                .packEncryptedEnvelope(message, aliceDid, faberDid)
            log.info { "Packed: ${packed.prettyPrint()}" }

            val unpackedJson = String(Crypto.unpackMessage(faber, packed.toByteArray()).get())
            val unpacked = unpackedJson.decodeJson()
            log.info { "Unpacked: $unpacked"}
            unpacked["message"] shouldBe message
            unpacked["recipient_verkey"] shouldBe faberDid.verkey
            unpacked["sender_verkey"] shouldBe aliceDid.verkey

        } finally {
            closeAndDeleteWallet(Faber.name)
            removeWallet(alice)
        }
    }

}

