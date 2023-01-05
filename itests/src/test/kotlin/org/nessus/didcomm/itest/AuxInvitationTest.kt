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

import com.google.gson.JsonObject
import org.apache.camel.Processor
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.nessus.didcomm.agent.AriesAgentService
import org.nessus.didcomm.agent.NessusAgentService
import org.nessus.didcomm.service.ARIES_AGENT_SERVICE_KEY
import org.nessus.didcomm.service.NESSUS_AGENT_SERVICE_KEY
import org.nessus.didcomm.service.ServiceRegistry
import org.nessus.didcomm.service.WALLET_SERVICE_KEY
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
        val inviterDid = inviter.createDid(seed=inviterSeed).did
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
            check("application/didcomm-envelope-enc" == headers["Content-Type"])
            val body = ex.message.getBody(String::class.java)
            // [TODO] MalformedMessageException: The header "id" is missing
            // val msg = MessageReader.fromJson(body)
            //
            // It seems we are getting a message defined in
            // https://github.com/hyperledger/aries-rfcs/blob/main/features/0019-encryption-envelope/README.md
            //
            // {
            //    "protected": "eyJlbmMiOiJ4Y2hhY2hhMjBwb2x5MTMwNV9pZXRmIiwidHlwIjoiSldNLzEuMCIsImFsZyI6IkF1dGhjcnlwdCIsInJlY2lwaWVudHMiOlt7ImVuY3J5cHRlZF9rZXkiOiJMNVhEaEgxNVBtX3ZIeFNlcmFZOGVPVEc2UmZjRTJOUTNFVGVWQy03RWlEWnl6cFJKZDhGVzBhNnFlNEpmdUF6IiwiaGVhZGVyIjp7ImtpZCI6IkdKMVN6b1d6YXZRWWZOTDlYa2FKZHJRZWpmenRONFhxZHNpVjRjdDNMWEtMIiwiaXYiOiJhOEltaW5zdFhIaTU0X0otSmU1SVdsT2NOZ1N3RDlUQiIsInNlbmRlciI6ImZ0aW13aWlZUkc3clJRYlhnSjEzQzVhVEVRSXJzV0RJX2JzeERxaVdiVGxWU0tQbXc2NDE4dnozSG1NbGVsTThBdVNpS2xhTENtUkRJNHNERlNnWkljQVZYbzEzNFY4bzhsRm9WMUJkREk3ZmRLT1p6ckticUNpeEtKaz0ifX0seyJlbmNyeXB0ZWRfa2V5IjoiZUFNaUQ2R0RtT3R6UkVoSS1UVjA1X1JoaXBweThqd09BdTVELTJJZFZPSmdJOC1ON1FOU3VsWXlDb1dpRTE2WSIsImhlYWRlciI6eyJraWQiOiJIS1RBaVlNOGNFMmtLQzlLYU5NWkxZajRHUzh1V0NZTUJ4UDJpMVk5Mnp1bSIsIml2IjoiRDR0TnRIZDJyczY1RUdfQTRHQi1vMC05QmdMeERNZkgiLCJzZW5kZXIiOiJzSjdwaXU0VUR1TF9vMnBYYi1KX0pBcHhzYUZyeGlUbWdwWmpsdFdqWUZUVWlyNGI4TVdtRGR0enAwT25UZUhMSzltRnJoSDRHVkExd1Z0bm9rVUtvZ0NkTldIc2NhclFzY1FDUlBaREtyVzZib2Z0d0g4X0VZR1RMMFE9In19XX0=",
            //    "iv": "ZqOrBZiA-RdFMhy2",
            //    "ciphertext": "K7KxkeYGtQpbi-gNuLObS8w724mIDP7IyGV_aN5AscnGumFd-SvBhW2WRIcOyHQmYa-wJX0MSGOJgc8FYw5UOQgtPAIMbSwVgq-8rF2hIniZMgdQBKxT_jGZS06kSHDy9UEYcDOswtoLgLp8YPU7HmScKHSpwYY3vPZQzgSS_n7Oa3o_jYiRKZF0Gemamue0e2iJ9xQIOPodsxLXxkPrvvdEIM0fJFrpbeuiKpMk",
            //    "tag": "kAuPl8mwb0FFVyip1omEhQ=="
            //}
            //
            val msgJson = gson.fromJson(body, JsonObject::class.java)
            log.info { prettyGson.toJson(msgJson) }
            latch.countDown()
        }

        val nessusAgent = ServiceRegistry.nessusAgentService()
        nessusAgent.startEndpoint(processor).use {
            val options = mapOf("auto_accept" to true)
            inviteeClient.post("/out-of-band/receive-invitation", message, options)
            assertTrue(latch.await(3, TimeUnit.SECONDS), "No receive-invitation response")
        }
    }
}
