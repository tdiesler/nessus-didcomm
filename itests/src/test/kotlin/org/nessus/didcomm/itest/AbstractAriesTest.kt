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

import mu.KotlinLogging
import org.hyperledger.aries.api.multitenancy.CreateWalletTokenRequest
import org.nessus.didcomm.agent.aries.AriesAgentService
import org.nessus.didcomm.service.*
import org.nessus.didcomm.wallet.LedgerRole
import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.NessusWalletBuilder

abstract class AbstractAriesTest {

    val log = KotlinLogging.logger {}

    companion object {
        const val GOVERNMENT = "Government"
        const val FABER = "Faber"
        const val ALICE = "Alice"

        fun onboardWallet(name: String, role: LedgerRole? = null, trustee: NessusWallet? = null) : NessusWallet {

            // Create ENDORSER wallets
            val builder = NessusWalletBuilder(name)
            if (role != null && trustee != null) {
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
                walletService().removeWallet(wallet.walletId)
            }
        }
    }

    fun getWallet(id: String): NessusWallet? {
        return walletService().getWallet(id)
    }

    fun getWalletByName(name: String): NessusWallet? {
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
        return wallet
    }
}
