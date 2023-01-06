/*-
 * #%L
 * Nessus DIDComm :: ITests
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
import org.apache.camel.Processor
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.nessus.didcomm.agent.AriesAgentService
import org.nessus.didcomm.agent.NessusAgentService
import org.nessus.didcomm.service.ARIES_AGENT_SERVICE_KEY
import org.nessus.didcomm.service.NESSUS_AGENT_SERVICE_KEY
import org.nessus.didcomm.service.ServiceRegistry
import org.nessus.didcomm.service.WALLET_SERVICE_KEY
import org.nessus.didcomm.util.decodeBase64Str
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.NessusWalletFactory
import org.nessus.didcomm.wallet.NessusWalletService
import org.nessus.didcomm.wallet.WalletAgent
import org.nessus.didcomm.wallet.WalletType
import org.nessus.didcomm.wallet.createUUID
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * DIDComm - Out Of Band Messages
 * https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages
 *
 * Aries RFC 0434: Out-of-Band Protocol 1.1
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0434-outofband
 *
 * Aries RFC 0023: DID Exchange Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
 *
 * Flow Overview
 * 1. The responder gives provisional information to the requester using an explicit invitation message from the
 *    out-of-band protocol or an implicit invitation in a DID the responder publishes.
 * 2. The requester uses the provisional information to send a DID and DID Doc to the responder in a request message.
 * 3. The responder uses sent DID Doc information to send a DID and DID Doc to the requester in a response message.
 * 4. The requester sends the responder a complete message that confirms the response message was received.
 */
class AuxInvitationTest : AbstractIntegrationTest() {

    companion object {
        @BeforeAll
        @JvmStatic
        internal fun beforeAll() {
            ServiceRegistry.putService(ARIES_AGENT_SERVICE_KEY, AriesAgentService())
            ServiceRegistry.putService(NESSUS_AGENT_SERVICE_KEY, NessusAgentService())
            ServiceRegistry.putService(WALLET_SERVICE_KEY, NessusWalletService())
        }
    }

    @Test
    fun test_AliceDidKeyNessus() {

        val invitee = getWalletByName(FABER)
        checkNotNull(invitee) { "No invitee wallet" }

        val inviteeClient = walletClient(invitee)

        val inviter: NessusWallet = NessusWalletFactory(ALICE)
            .walletAgent(WalletAgent.NESSUS)
            .walletType(WalletType.IN_MEMORY)
            .create()

        val inviterSeed = "00000000000000000000000000Alice1"
        val inviterEndpoint = "http://host.docker.internal:9030"
        val inviterDid = inviter.createDid(seed=inviterSeed)
        assertEquals("did:key:z6Mksu6Kco9yky1pUAWnWyer17bnokrLL3bYvYFp27zv8WNv", inviterDid.qualified)
        assertEquals("ESqH2YuYRRXMMfg5qQh1A23nzBaUvAMCEXLtBr2uDHbY", inviterDid.verkey)

        val message = """
        {
          "@id": "${createUUID()}",
          "@type": "https://didcomm.org/out-of-band/1.1/invitation",
          "goal_code": "Issue a Faber College Graduate credential",
          "accept": [ "didcomm/v2" ],
          "handshake_protocols": [ "https://didcomm.org/didexchange/1.0" ],
          "services": [
            {
              "id": "#inline",
              "type": "did-communication",
              "recipientKeys": [ "${inviterDid.qualified}" ],
              "serviceEndpoint": "$inviterEndpoint"
            }
          ]
        }
        """.trimIndent()

        val latch = CountDownLatch(1)
        val processor = Processor { ex ->
            val headers = ex.message.headers
            log.info("headers={}, body={}", headers)
            val contentType = headers["Content-Type"] as String
            val msgBody = ex.message.getBody(String::class.java)
            messageHandler(contentType, msgBody)
            latch.countDown()
        }

        val nessusAgent = ServiceRegistry.nessusAgentService()
        nessusAgent.startEndpoint(processor).use {
            val options = mapOf("auto_accept" to true)
            inviteeClient.post("/out-of-band/receive-invitation", message, options)
            assertTrue(latch.await(3, TimeUnit.SECONDS), "No receive-invitation response")
        }
    }

    private fun messageHandler(contentType: String, msgBody: String) {
        log.info { "Content-Type: $contentType" }
        log.info { msgBody.prettyPrint() }
        when(contentType) {
            "application/didcomm-envelope-enc" -> didcommEncryptedEnvelopeHandler(contentType, msgBody)
            else -> throw IllegalStateException("Unsupported content type: $contentType")
        }
    }

    /**
     * Unpack Algorithm
     * https://github.com/hyperledger/aries-rfcs/tree/main/features/0019-encryption-envelope#unpack-algorithm
     * ----------------
     *
     * 1. Serialize data, so it can be used
     *
     * 2. Lookup the `kid` for each recipient in the wallet to see if the wallet possesses a private key
     *    associated with the public key listed
     *
     * 3. Check if a `sender` field is used.
     *    - If a sender is included use auth_decrypt to decrypt the `encrypted_key` by doing the following:
     *      a. decrypt sender verkey using libsodium.crypto_box_seal_open(my_private_key, base64URLdecode(sender))
     *      b. decrypt cek using libsodium.crypto_box_open(my_private_key, sender_verkey, encrypted_key, cek_iv)
     *      c. decrypt ciphertext using
     *         libsodium.crypto_aead_chacha20poly1305_ietf_open_detached(
     *              base64URLdecode(ciphertext_bytes),
     *              base64URLdecode(protected_data_as_bytes),
     *              base64URLdecode(nonce), cek)
     *      d. return `message`, `recipient_verkey` and `sender_verkey` following the authcrypt format listed below
     *
     *    - If a sender is NOT included use anon_decrypt to decrypt the `encrypted_key` by doing the following:
     *      a. decrypt encrypted_key using libsodium.crypto_box_seal_open(my_private_key, encrypted_key)
     *      b. decrypt ciphertext using
     *         libsodium.crypto_aead_chacha20poly1305_ietf_open_detached(
     *              base64URLdecode(ciphertext_bytes),
     *              base64URLdecode(protected_data_as_bytes),
     *              base64URLdecode(nonce), cek)
     *      c. return message and recipient_verkey following the anoncrypt format listed below
     *
     * NOTE: In the unpack algorithm, the base64url decode implementation used MUST correctly decode
     * padded and unpadded base64URL encoded data.
     */
    private fun didcommEncryptedEnvelopeHandler(contentType: String, msgBody: String) {
        require("application/didcomm-envelope-enc" == contentType)

        // Serialize data, so it can be used
        val msgJson = msgBody.decodeJson()

        val protected64 = msgJson["protected"] as? String ?: "No `protected` in $msgJson"
        val protected =  protected64.decodeBase64Str().decodeJson()
        log.info { protected.prettyPrint() }
        val recipients = protected["recipients"] as List<MapElement>

        // Lookup the `kid` for each recipient in the wallet to see if the wallet possesses a private key
        // associated with the public key listed
        recipients.forEach {
            val header = it["header"] as MapElement
            val kid58 = header["kid"]
            val sender64 = header["sender"]
            if (sender64 != null) {

            }
        }

        val iv = msgJson["iv"] as? String ?: "No `iv` in $msgJson"
        val ciphertext = msgJson["ciphertext"] as? String ?: "No `tag` ciphertext $msgJson"
        val tag = msgJson["tag"] as? String ?: "No `tag` in $msgJson"


    }
}

typealias MapElement = Map<String, String>
