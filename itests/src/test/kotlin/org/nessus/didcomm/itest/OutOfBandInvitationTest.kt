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
import org.hyperledger.aries.api.out_of_band.InvitationMessage.InvitationMessageService
import org.hyperledger.aries.api.out_of_band.ReceiveInvitationFilter
import org.junit.jupiter.api.Test
import org.nessus.didcomm.agent.AriesAgent
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.prettyGson
import org.nessus.didcomm.wallet.DidMethod
import org.nessus.didcomm.wallet.LedgerRole
import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.WalletType
import kotlin.test.assertEquals

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
 * DID Exchange - Flow Overview
 * 1. The invitee gives provisional information to the inviter using an explicit invitation message from the
 *    out-of-band protocol or an implicit invitation in a DID the invitee publishes.
 * 2. The inviter uses the provisional information to send a DID and DID Doc to the invitee in a request message.
 * 3. The invitee uses sent DID Doc information to send a DID and DID Doc to the inviter in a response message.
 * 4. The inviter sends the invitee a complete message that confirms the response message was received.
 */
class OutOfBandInvitationTest : AbstractIntegrationTest() {

    @Test
    fun test_FaberDidSovIndyPubAuto_AliceDidKeyIndyAuto() {

        runDidExchangeConfig(mapOf(

            "inviterWalletName" to Faber.name,
            "inviterUsePublicDid" to true,
            "inviterAutoAccept" to true,

            "inviteeWalletName" to Alice.name,
            "inviteeWalletType" to WalletType.INDY,
            "inviteeDidMethod" to DidMethod.KEY,
            "inviteeAutoAccept" to true))
    }

    @Test
    fun test_AliceDidKeyMemoryAuto_FaberDidSovIndyPubAuto() {

        runDidExchangeConfig(mapOf(

            "inviterWalletName" to Alice.name,
            "inviterWalletType" to WalletType.IN_MEMORY,
            "inviterDidMethod" to DidMethod.KEY,
            "inviterAutoAccept" to true,

            "inviteeWalletName" to Faber.name,
            "inviteeUsePublicDid" to true,
            "inviteeAutoAccept" to true))
    }

    private fun runDidExchangeConfig(config: Map<String, Any?>) {

        val inviterWalletName = config["inviterWalletName"] as String
        val inviterWalletType = config["inviterWalletType"] as WalletType?
        val inviterDidMethod = config["inviterDidMethod"] as DidMethod?
        val inviterLedgerRole = config["inviterLedgerRole"] as LedgerRole?
        val inviterUsePublicDid = config["inviterUsePublicDid"] as Boolean? ?: false

        val inviteeWalletName = config["inviteeWalletName"] as String
        val inviteeWalletType = config["inviteeWalletType"] as WalletType?
        val inviteeDidMethod = config["inviteeDidMethod"] as DidMethod?
        val inviteeLedgerRole = config["inviteeLedgerRole"] as LedgerRole?
        val inviteeUsePublicDid = config["inviteeUsePublicDid"] as Boolean? ?: false

        val trustee = getWalletByName(Government.name)
        checkNotNull(trustee) { "No Government/Trustee" }

        val faber = getWalletByName(Faber.name)
        checkNotNull(faber) { "No Faber/Endorser" }

        val inviter = if (inviterWalletName == Faber.name) faber
            else NessusWallet.Builder(inviterWalletName)
                .walletType(inviterWalletType)
                .didMethod(inviterDidMethod)
                .ledgerRole(inviterLedgerRole)
                .publicDid(inviterUsePublicDid)
                .trusteeWallet(trustee)
                .build()

        val invitee = if (inviteeWalletName == Faber.name) faber
            else NessusWallet.Builder(inviteeWalletName)
                .walletType(inviteeWalletType)
                .didMethod(inviteeDidMethod)
                .ledgerRole(inviteeLedgerRole)
                .publicDid(inviteeUsePublicDid)
                .trusteeWallet(trustee)
                .build()

        try {

            val result = didExchange(inviter, invitee, config)

            val inviterConnection = result["inviterConnection"] as ConnectionRecord?
            val inviteeConnection = result["inviteeConnection"] as ConnectionRecord?

            log.info("$inviterWalletName: {}", inviterConnection?.prettyPrint())
            log.info("$inviteeWalletName: {}", inviteeConnection?.prettyPrint())

            assertEquals(ConnectionState.ACTIVE, inviterConnection?.state)
            assertEquals(ConnectionState.ACTIVE, inviteeConnection?.state)

        } finally {
            val faberClient = AriesAgent.walletClient(getWalletByName(Faber.name)!!)
            faberClient.connections().get().forEach {
                faberClient.connectionsRemove(it.connectionId)
            }
            removeWallet(getWalletByName(Alice.name))
        }
    }

    private fun didExchange(inviter: NessusWallet, invitee: NessusWallet, config: Map<String, Any?>): Map<String, Any> {

        log.info("Running {}", config)

        val inviterWalletName = config["inviterWalletName"] as String
        val inviterAutoAccept = config["inviterAutoAccept"] as Boolean
        val inviterUsePublicDid = config["inviterUsePublicDid"] as Boolean? ?: false

        val inviteeWalletName = config["inviteeWalletName"] as String
        val inviteeAutoAccept = config["inviteeAutoAccept"] as Boolean

        val inviterClient = AriesAgent.walletClient(inviter)
        val inviteeClient = AriesAgent.walletClient(invitee)

        // Inviter creates the Invitation
        //
        val createInvRequest = InvitationCreateRequest.builder()
            .accept(listOf("didcomm/v2"))
            .alias("$inviterWalletName/$inviteeWalletName")
            .myLabel("Invitation for $inviteeWalletName")
            .handshakeProtocols(listOf("https://didcomm.org/didexchange/1.0"))
            .protocolVersion("1.1")
            .usePublicDid(inviterUsePublicDid)
            .build()
        val createInvFilter = CreateInvitationFilter.builder()
            .autoAccept(inviterAutoAccept)
            .build()
        val inviterInvRecord: InvitationRecord = inviterClient.outOfBandCreateInvitation(createInvRequest, createInvFilter).get()
        val inviterInvitation = inviterInvRecord.invitation
        val invitationMsgId = inviterInvRecord.inviMsgId

        // Invitee receives the Invitation
        //
        val invitationMessageBuilder = if (inviterUsePublicDid) {
            InvitationMessage.builder<String>()
                .services(inviterInvitation.services.map { it as String })
        } else {
            InvitationMessage.builder<InvitationMessageService>()
                .services(inviterInvitation.services.map {
                    val srvJson: String = gson.toJson(it)
                    gson.fromJson(srvJson, InvitationMessageService::class.java)
                })
        }

        // [TODO] `from` is required by didcomm-v2 spec
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

        // [TODO] should this really return a ConnectionRecord?
        var inviteeConnection = inviteeClient.outOfBandReceiveInvitation(invitationMessage, receiveInvFilter).get()

        // Invitee manually accepts the Invitation
        //
        if (!inviteeAutoAccept) {
            val inviteeEndpoint = "http://host.docker.internal:8030"
            val connectionId = inviteeConnection.connectionId
            val acceptInvitationFilter = DidExchangeAcceptInvitationFilter()
            acceptInvitationFilter.myEndpoint = inviteeEndpoint
            inviteeClient.didExchangeAcceptInvitation(connectionId, acceptInvitationFilter).get()
        }

        // Invitee awaits active Connection
        //
        inviteeConnection = awaitConnectionRecord(inviteeClient) {
            it.invitationMsgId == invitationMsgId && it.stateIsActive()
        } ?: throw IllegalStateException("Invitee has no connection record in state 'active'")
        log.info("$inviteeWalletName: {}", prettyGson.toJson(inviteeConnection))

        // Inviter awaits active Connection
        //
        val inviterConnection = awaitConnectionRecord(inviterClient) {
            it.invitationMsgId == invitationMsgId && it.stateIsActive()
        } ?: throw IllegalStateException("Inviter has no connection record in state 'active'")
        log.info("$inviterWalletName: {}", prettyGson.toJson(inviterConnection))

        return mapOf(
            "inviterConnection" to inviterConnection,
            "inviteeConnection" to inviteeConnection,
        )
    }
}
