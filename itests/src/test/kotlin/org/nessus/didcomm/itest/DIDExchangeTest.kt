package org.nessus.didcomm.itest

import mu.KotlinLogging
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.hyperledger.acy_py.generated.model.InvitationRecord
import org.junit.jupiter.api.AfterAll
import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.nessus.didcomm.agent.aries.AriesAgentService
import org.nessus.didcomm.agent.aries.AriesWalletService
import org.nessus.didcomm.model.MessageReader
import org.nessus.didcomm.model.MessageType.Companion.OUT_OF_BAND_INVITATION
import org.nessus.didcomm.model.MessageWriter
import org.nessus.didcomm.service.AgentService
import org.nessus.didcomm.service.ServiceRegistry
import org.nessus.didcomm.wallet.LedgerRole
import org.nessus.didcomm.wallet.NessusWallet
import kotlin.test.assertEquals

/**
 * Aries RFC 0023: DID Exchange Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
 */
class DIDExchangeTest : AbstractAriesTest() {

    companion object {
        @BeforeAll
        @JvmStatic
        internal fun beforeAll() {
            ServiceRegistry.addService(AriesAgentService())
            ServiceRegistry.addService(AriesWalletService())
        }
    }

    @Test
    fun testFaberInvitesAlice() {

        val faber = getWalletByName(FABER)!!
        val alice = getWalletByName(ALICE)!!

        // Create the OOB Invitation through the Agent
        val body = MessageWriter.toMutableMap("""
            {
                "goal_code": "did-exchange",
                "goal": "Faber College invites you for a DID exchange",
                "accept": [ "didcomm/v2" ]
            }
        """.trimIndent())
        val msg: Message = agentService().createMessage(faber, OUT_OF_BAND_INVITATION, body)

        // Verify the DCV2 message
        val att0: Attachment = msg.attachments?.get(0)!!
        val invJson = MessageWriter.toJson(att0.data.toJSONObject()["json"]!!)
        val invRec: InvitationRecord = MessageReader.fromJson(invJson, InvitationRecord::class.java)
        assertEquals(att0.id, invRec.inviMsgId)
    }
}
