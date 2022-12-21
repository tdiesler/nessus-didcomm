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
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.wallet.LedgerRole
import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.NessusWalletBuilder
import kotlin.test.assertEquals

class Scenario001Test : AbstractAriesTest() {

    companion object {
        private val log = KotlinLogging.logger {}

        var governmentWallet: NessusWallet? = null
        var faberWallet: NessusWallet? = null

        @BeforeAll
        @JvmStatic
        internal fun beforeAll() {
            ServiceRegistry.addService(AriesAgentService())
            ServiceRegistry.addService(AriesWalletService())

            // Create initial TRUSTEE Wallet
            governmentWallet = NessusWalletBuilder("Government")
                .ledgerRole(LedgerRole.TRUSTEE)
                .selfRegisterNym()
                .build()

            // Onboard an ENDORSER wallet
            faberWallet = NessusWalletBuilder("Faber")
                .trusteeWallet(governmentWallet!!)
                .ledgerRole(LedgerRole.ENDORSER)
                .build()

            val did = faberWallet?.publicDid()
            log.info("Faber: Public {}", did)
        }

        @AfterAll
        @JvmStatic
        internal fun afterAll() {
            val walletService = ServiceRegistry.getService(WalletService.type)
            walletService.closeAndRemove(faberWallet)
            walletService.closeAndRemove(governmentWallet)
        }
    }

    @Test
    fun testFaberInvitesAlice() {

        // Create the OOB Invitation through the Agent
        val body = MessageWriter.toMutableMap("""
            {
                "goal_code": "did-exchange",
                "goal": "Faber College invites you for a DID exchange",
                "accept": [ "didcomm/v2" ]
            }
        """.trimIndent())
        val agent = ServiceRegistry.getService(AgentService.type)
        val msg: Message = agent.createMessage(faberWallet!!, OUT_OF_BAND_INVITATION, body)

        // Verify the DCV2 message
        val att0: Attachment = msg.attachments?.get(0)!!
        val invJson = MessageWriter.toJson(att0.data.toJSONObject()["json"]!!)
        val invRec: InvitationRecord = MessageReader.fromJson(invJson, InvitationRecord::class.java)
        assertEquals(att0.id, invRec.inviMsgId)
    }
}
