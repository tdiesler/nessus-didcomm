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
import org.hyperledger.aries.api.connection.ConnectionRecord
import org.hyperledger.aries.api.connection.ConnectionState
import org.hyperledger.aries.api.did_exchange.DidExchangeCreateRequestFilter
import org.junit.jupiter.api.Test
import org.nessus.didcomm.agent.AriesAgent
import org.nessus.didcomm.util.prettyGson
import org.nessus.didcomm.wallet.DidMethod
import org.nessus.didcomm.wallet.NessusWallet
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
class DidExchangeRequestTest : AbstractIntegrationTest() {

    @Test
    fun didExchange_Faber_Alice() {

        // Assert that Faber has a public did:sov on Indy
        val faber = getWalletByName(Faber.name) ?: fail("Faber does not exist")
        faber.publicDid ?: fail("Faber has no public DID")

        val alice = NessusWallet.Builder(Alice.name)
            .walletType(WalletType.INDY)
            .didMethod(DidMethod.KEY)
            .build()

        try {

            val result = didExchange(faber, alice)

            val aliceConnection = result["aliceConnection"] as ConnectionRecord?
            val faberConnection = result["faberConnection"] as ConnectionRecord?

            log.info("Alice: {}", aliceConnection?.prettyPrint())
            log.info("Faber: {}", faberConnection?.prettyPrint())

            assertEquals(ConnectionState.ACTIVE, aliceConnection?.state)
            assertEquals(ConnectionState.ACTIVE, faberConnection?.state)

        } finally {
            val faberClient = AriesAgent.walletClient(faber)
            faberClient.connections().get().forEach {
                faberClient.connectionsRemove(it.connectionId)
            }
            removeWallet(alice)
        }
    }

    private fun didExchange(faber: NessusWallet, alice: NessusWallet): Map<String, Any> {

        val faberPublicDid = faber.publicDid?.qualified
        checkNotNull(faberPublicDid) { "No public did for Faber" }

        val faberClient = AriesAgent.walletClient(faber)
        val aliceClient = AriesAgent.walletClient(alice)

        val createReqFilter = DidExchangeCreateRequestFilter.builder()
            .myEndpoint("http://host.docker.internal:8030")
            .theirPublicDid(faberPublicDid)
            .build()

        var aliceConnection = aliceClient.didExchangeCreateRequest(createReqFilter).get()
        val requestId = aliceConnection.requestId

        aliceConnection = awaitConnectionRecord(aliceClient) {
            it.requestId == requestId && it.stateIsActive()
        } ?: throw IllegalStateException("Alice has no connection record in state 'active'")
        log.info("Alice: {}", prettyGson.toJson(aliceConnection))

        val faberConnection = awaitConnectionRecord(faberClient) {
            it.requestId == requestId && it.stateIsActive()
        } ?: throw IllegalStateException("Faber has no connection record in state 'active'")
        log.info("Faber: {}", prettyGson.toJson(faberConnection))

        return mapOf(
            "aliceWallet" to alice,
            "aliceConnection" to aliceConnection,
            "faberConnection" to faberConnection,
        )
    }
}
