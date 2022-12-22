package org.nessus.didcomm.itest

import mu.KotlinLogging
import org.hyperledger.aries.api.multitenancy.CreateWalletTokenRequest
import org.nessus.didcomm.agent.aries.AriesAgentService
import org.nessus.didcomm.service.AgentService
import org.nessus.didcomm.service.ServiceRegistry
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.wallet.LedgerRole
import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.NessusWalletBuilder

abstract class AbstractAriesTest {

    val log = KotlinLogging.logger {}

    companion object {
        const val GOVERNMENT = "Government"
        const val FABER = "Faber"
        const val ALICE = "Alice"

        fun onboardWallet(name: String, role: LedgerRole? = null, trustee: NessusWallet? = null, ifNotExist: Boolean = true) : NessusWallet {

            // Create initial TRUSTEE wallet
            val builder = NessusWalletBuilder(name)
            if (role == LedgerRole.TRUSTEE) {
                builder.ledgerRole(role).selfRegisterNym()
            }
            // Create ENDORSER wallets
            else if (role != null && trustee != null) {
                builder.ledgerRole(role).trusteeWallet(trustee)
            }
            // Simple wallets
            else {
                // with just the name
            }
            return builder.build()
        }

        fun removeWallet(wallet: NessusWallet?) {
            if (wallet != null) {
                val walletService = ServiceRegistry.getService(WalletService.type)
                walletService.removeWallet(wallet!!.walletId)
            }
        }
    }

    fun getWallet(id: String): NessusWallet? {
        return walletService().getWallet(id)
    }

    fun getWalletByName(name: String, create: Boolean = true): NessusWallet? {
        val agent = agentService()
        var wallet = walletService().getWalletByName(name)
        if (wallet == null && agentService() is AriesAgentService) {
            val adminClient = AriesAgentService.adminClient()
            val walletRecord = adminClient.multitenancyWallets(name).get().firstOrNull()
            if (walletRecord != null) {
                val walletId = walletRecord.walletId
                val tokReq = CreateWalletTokenRequest.builder().build()
                val tokRes = adminClient.multitenancyWalletToken(walletId, tokReq).get()
                wallet = NessusWallet(walletId, name, tokRes.token)
            }
        }
        if (wallet == null && create) {
            when(name) {
                GOVERNMENT -> wallet = onboardWallet(GOVERNMENT, LedgerRole.TRUSTEE)
                FABER -> wallet = onboardWallet(FABER, LedgerRole.TRUSTEE)
                else -> onboardWallet(name)
            }
        }
        return wallet
    }

    fun agentService(): AgentService {
        return ServiceRegistry.getService(AgentService.type)
    }

    fun walletService(): WalletService {
        return ServiceRegistry.getService(WalletService.type)
    }
}
