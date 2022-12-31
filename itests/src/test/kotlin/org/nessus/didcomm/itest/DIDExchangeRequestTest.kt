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

import org.hyperledger.aries.api.connection.ConnectionRecord
import org.hyperledger.aries.api.connection.ConnectionState
import org.hyperledger.aries.api.did_exchange.DidExchangeCreateRequestFilter
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.nessus.didcomm.agent.AriesAgentService
import org.nessus.didcomm.agent.NessusAgentService
import org.nessus.didcomm.service.ARIES_AGENT_SERVICE_KEY
import org.nessus.didcomm.service.NESSUS_AGENT_SERVICE_KEY
import org.nessus.didcomm.service.ServiceRegistry
import org.nessus.didcomm.service.WALLET_SERVICE_KEY
import org.nessus.didcomm.wallet.DIDMethod
import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.NessusWalletFactory
import org.nessus.didcomm.wallet.NessusWalletService
import org.nessus.didcomm.wallet.WalletType
import kotlin.test.assertEquals
import kotlin.test.fail

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
class DIDExchangeRequestTest : AbstractAriesTest() {

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
    fun test_FaberPub_AliceKeyIndyNonAuto() {

        // Assert that Faber has a public did:sov on Indy
        val faber = getWalletByName(FABER) ?: fail("Faber does not exist")
        val faberPublicDid = faber.publicDid ?: fail("Faber has no public DID")
        assertEquals(WalletType.INDY, faber.walletType)
        assertEquals(DIDMethod.SOV, faberPublicDid.method)

        runDidExchangeConfig(faber, mapOf(
            "faberPublicDid" to faberPublicDid.qualified,
            "aliceWalletType" to WalletType.INDY,
            "aliceDidMethod" to DIDMethod.KEY))
    }

    private fun runDidExchangeConfig(faber: NessusWallet, config: Map<String, Any?>) {

        val aliceWalletType = config["aliceWalletType"] as WalletType
        val aliceDidMethod = config["aliceDidMethod"] as DIDMethod

        val alice = NessusWalletFactory(ALICE)
            .walletType(aliceWalletType)
            .didMethod(aliceDidMethod)
            .create()

        try {

            val result = didExchange(faber, alice, config)

            val aliceConnection = result["aliceConnection"] as ConnectionRecord?
            val faberConnection = result["faberConnection"] as ConnectionRecord?

            log.info("Alice: {}", prettyGson.toJson(aliceConnection))
            log.info("Faber: {}", prettyGson.toJson(faberConnection))

            assertEquals(ConnectionState.ACTIVE, aliceConnection?.state)
            assertEquals(ConnectionState.ACTIVE, faberConnection?.state)

        } finally {
            val faberClient = walletClient(faber)
            faberClient.connections().get().forEach {
                faberClient.connectionsRemove(it.connectionId)
            }
            removeWallet(alice)
        }
    }

    private fun didExchange(faber: NessusWallet, alice: NessusWallet, config: Map<String, Any?>): Map<String, Any> {

        log.info("Running {}", config)

        val faberPublicDid = config["faberPublicDid"] as String?

        val faberClient = walletClient(faber)
        val aliceClient = walletClient(alice)

        val aliceEndpoint = "http://host.docker.internal:8030"
        val createReqFilter = DidExchangeCreateRequestFilter.builder()
            .theirPublicDid(faberPublicDid ?: throw IllegalStateException("No public did for Faber"))
            .myEndpoint(aliceEndpoint)
            .usePublicDid(false)
            .build()
        aliceClient.didExchangeCreateRequest(createReqFilter).get()

        val aliceConnRecord = awaitConnectionRecord(aliceClient) {
            it.stateIsActive()
        } ?: throw IllegalStateException("Alice has no connection record in state 'active'")
        log.info("Alice: {}", prettyGson.toJson(aliceConnRecord))

        val faberConnRecord = awaitConnectionRecord(faberClient) {
            it.stateIsActive()
        } ?: throw IllegalStateException("Faber has no connection record in state 'active'")
        log.info("Faber: {}", prettyGson.toJson(faberConnRecord))

        return mapOf(
            "aliceWallet" to alice,
            "aliceConnection" to aliceConnRecord,
            "faberConnection" to faberConnRecord,
        )
    }
}
