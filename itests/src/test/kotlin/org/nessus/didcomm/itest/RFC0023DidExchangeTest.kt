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
import org.hyperledger.acy_py.generated.model.InvitationRecord
import org.hyperledger.aries.api.connection.ConnectionRecord
import org.hyperledger.aries.api.connection.ConnectionState
import org.hyperledger.aries.api.did_exchange.DidExchangeAcceptInvitationFilter
import org.hyperledger.aries.api.out_of_band.CreateInvitationFilter
import org.hyperledger.aries.api.out_of_band.InvitationCreateRequest
import org.hyperledger.aries.api.out_of_band.InvitationMessage
import org.hyperledger.aries.api.out_of_band.ReceiveInvitationFilter
import org.junit.jupiter.api.Test
import org.nessus.didcomm.agent.AriesAgent.Companion.awaitConnectionRecord
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.prettyGson
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.StorageType
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
class RFC0023DidExchangeTest : AbstractIntegrationTest() {

    @Test
    fun didExchange_FaberAcapy_AliceAcapy() {

        /**
         * Findings
         *
         * - When Faber uses a public DID, Alice needs to have an INDY wallet as well in order to resolve that DID
         */

        val inviter = getWalletByAlias(Faber.name) ?: fail("Faber does not exist")

        val invitee = Wallet.Builder(Alice.name)
            .agentType(AgentType.ACAPY)
            .storageType(StorageType.IN_MEMORY)
            .build()

        try {

            val result = didExchange(inviter, invitee)

            val inviterConnection = result["inviterConnection"] as ConnectionRecord?
            val inviteeConnection = result["inviteeConnection"] as ConnectionRecord?

            log.info("${inviter.alias}: ${inviterConnection?.prettyPrint()}")
            log.info("${invitee.alias}: ${inviteeConnection?.prettyPrint()}")

            assertEquals(ConnectionState.ACTIVE, inviterConnection?.state)
            assertEquals(ConnectionState.ACTIVE, inviteeConnection?.state)

        } finally {
            inviter.removeConnections()
            removeWallet(invitee)
        }
    }

    private fun didExchange(inviter: Wallet, invitee: Wallet): Map<String, Any> {

        val inviterClient = inviter.walletClient() as AriesClient
        val inviteeClient = invitee.walletClient() as AriesClient

        val inviterAutoAccept = true
        val inviteeAutoAccept = false

        /**
         * Inviter (Faber) creates an Out-of-Band Invitation
         */

        val createInvRequest = InvitationCreateRequest.builder()
            .accept(listOf("didcomm/v2"))
            .alias("${inviter.alias}/${invitee.alias}")
            .myLabel("Invitation for ${invitee.alias}")
            .handshakeProtocols(listOf("https://didcomm.org/didexchange/1.0"))
            .protocolVersion("1.1")
            .usePublicDid(false)
            .build()
        val createInvFilter = CreateInvitationFilter.builder()
            .autoAccept(inviterAutoAccept)
            .build()
        val inviterInvRecord: InvitationRecord = inviterClient.outOfBandCreateInvitation(createInvRequest, createInvFilter).get()
        val inviterInvitation = inviterInvRecord.invitation
        val invitationMsgId = inviterInvRecord.inviMsgId

        // Expect inviter connection in state 'invitation'
        var inviterConnection = awaitConnectionRecord(inviter) {
            it.invitationMsgId == invitationMsgId && it.stateIsInvitation()
        }
        checkNotNull(inviterConnection) {"${inviter.alias} has no connection record in state 'invitation'"}
        log.info {"${inviter.alias} connection: ${inviterConnection?.state}"}
        log.info("${inviter.alias}: {}", prettyGson.toJson(inviterConnection))

        /**
         * Invitee (Alice) receives the Invitation
         */

        val invitationMessageBuilder = InvitationMessage.builder<InvitationMessage.InvitationMessageService>()
            .services(inviterInvitation.services.map {
                val srvJson: String = gson.toJson(it)
                gson.fromJson(srvJson, InvitationMessage.InvitationMessageService::class.java)
            })

        val invitationMessage = invitationMessageBuilder.atId(inviterInvitation.atId)
            .atType(inviterInvitation.atType)
            .goalCode("issue-vc")
            .goalCode("Issue a Faber College Graduate credential")
            .accept(inviterInvitation.accept)
            .build()

        val receiveInvFilter = ReceiveInvitationFilter.builder()
            .useExistingConnection(false)
            .autoAccept(inviteeAutoAccept)
            .build()
        inviteeClient.outOfBandReceiveInvitation(invitationMessage, receiveInvFilter).get()

        // Expect invitee connection in state 'invitation'
        var inviteeConnection = awaitConnectionRecord(invitee) {
            it.invitationMsgId == invitationMsgId && it.stateIsInvitation()
        }
        checkNotNull(inviteeConnection) {"${invitee.alias} has no connection record in state 'invitation'"}
        log.info {"${invitee.alias} connection: ${inviteeConnection?.state}"}
        log.info("${invitee.alias}: {}", prettyGson.toJson(inviteeConnection))

        /**
         * Invitee (Alice) manually accepts the Invitation
         */

        if (!inviteeAutoAccept) {
            val acceptInvitationFilter = DidExchangeAcceptInvitationFilter()
            acceptInvitationFilter.myEndpoint = "http://localhost:8030"
            acceptInvitationFilter.myLabel = "Accept Faber/Alice"
            val inviteeConnectionId = inviteeConnection.connectionId
            inviteeClient.didExchangeAcceptInvitation(inviteeConnectionId, acceptInvitationFilter).get()
        }

        /**
         * Inviter (Faber) manually accepts the Invitation
         *
         * Note, this will currently not work because of ...
         * No explicit invitation found for pairwise connection
         *
         * It seems that Faber needs to receive an oob invitation too.
         * We won't worry about this for now (i.e. Faber needs to auto_accept)
         */

        if (!inviterAutoAccept) {
            val acceptInvitationFilter = DidExchangeAcceptInvitationFilter()
            acceptInvitationFilter.myEndpoint = "http://localhost:8030"
            acceptInvitationFilter.myLabel = "Accept Faber/Alice"
            val inviterConnectionId = inviterConnection.connectionId
            inviterClient.didExchangeAcceptInvitation(inviterConnectionId, acceptInvitationFilter).get()
        }

        /**
         * Invitee (Alice) awaits her active Connection
         */

        inviteeConnection = awaitConnectionRecord(invitee) {
            it.invitationMsgId == invitationMsgId && it.stateIsActive()
        }
        checkNotNull(inviteeConnection) {"${invitee.alias} has no connection record in state 'active'"}
        log.info {"${invitee.alias} connection: ${inviteeConnection.state}"}
        log.info("${invitee.alias}: {}", prettyGson.toJson(inviteeConnection))

        /**
         * Inviter (Faber) awaits it's active Connection
         */

        inviterConnection = awaitConnectionRecord(inviter) {
            it.invitationMsgId == invitationMsgId && it.stateIsActive()
        }
        checkNotNull(inviterConnection) {"${inviter.alias} has no connection record in state 'active'"}
        log.info {"${inviter.alias} connection: ${inviterConnection.state}"}
        log.info("${inviter.alias}: {}", prettyGson.toJson(inviterConnection))

        return mapOf(
            "inviteeConnection" to inviteeConnection,
            "inviterConnection" to inviterConnection,
        )
    }
}
