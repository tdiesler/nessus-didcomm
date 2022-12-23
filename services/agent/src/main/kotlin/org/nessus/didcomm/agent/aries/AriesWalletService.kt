/*-
 * #%L
 * Nessus DIDComm :: Services :: Agent
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
package org.nessus.didcomm.agent.aries

import mu.KotlinLogging
import org.hyperledger.acy_py.generated.model.DID
import org.hyperledger.aries.AriesClient
import org.hyperledger.aries.api.ledger.IndyLedgerRoles
import org.hyperledger.aries.api.ledger.RegisterNymFilter
import org.hyperledger.aries.api.multitenancy.CreateWalletRequest
import org.hyperledger.aries.api.multitenancy.RemoveWalletRequest
import org.hyperledger.aries.api.multitenancy.WalletDispatchType
import org.hyperledger.aries.api.multitenancy.WalletType
import org.hyperledger.aries.api.wallet.WalletDIDCreate
import org.nessus.didcomm.agent.aries.AriesAgentService.Companion.adminClient
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.wallet.LedgerRole
import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.WalletException


class AriesWalletService : WalletService {

    private val log = KotlinLogging.logger {}

    override fun createWallet(walletName: String, config: Map<String, Any?>): NessusWallet {

        val walletKey = config["walletKey"] as? String ?: (walletName + "Key")
        val trusteeWallet = config["trusteeWallet"] as? NessusWallet
        val ledgerRole = config["ledgerRole"] as? LedgerRole
        val indyLedgerRole = if (ledgerRole != null) IndyLedgerRoles.valueOf(ledgerRole.toString()) else null

        val walletRequest = CreateWalletRequest.builder()
            .walletName(walletName)
            .walletKey(walletKey)
            .walletDispatchType(WalletDispatchType.DEFAULT)
            .walletType(WalletType.INDY)
            .build()
        val walletRecord = adminClient().multitenancyWalletCreate(walletRequest).get()
        val nessusWallet = NessusWallet(walletRecord.walletId, walletName, walletRecord.token)
        log.info("{}: [{}] {}", walletName, nessusWallet.walletId, nessusWallet)

        if (indyLedgerRole != null) {
            trusteeWallet ?: throw WalletException("LedgerRole $indyLedgerRole requires selfRegister or trusteeWallet")

            // Create a local DID for the wallet
            val walletClient = AriesAgentService.walletClient(nessusWallet)
            val did: DID = walletClient.walletDidCreate(WalletDIDCreate.builder().build()).get()
            log.info("{}: {}", walletName, did)

            val trustee: AriesClient = AriesAgentService.walletClient(trusteeWallet)
            val trusteeName: String = trusteeWallet.walletName
            val nymResponse = trustee.ledgerRegisterNym(
                RegisterNymFilter.builder()
                    .verkey(did.verkey)
                    .did(did.did)
                    .role(indyLedgerRole)
                    .build()
            ).get()
            log.info("{} for {}: {}", trusteeName, walletName, nymResponse)

            // Set the public DID for the wallet
            walletClient.walletDidPublic(did.did)
            val didEndpoint = walletClient.walletGetDidEndpoint(did.did).get()
            log.info("{}: {}", walletName, didEndpoint)
        }

        putWallet(nessusWallet)
        return nessusWallet
    }

    override fun publicDid(wallet: NessusWallet): String? {
        val walletClient = AriesAgentService.walletClient(wallet)
        val did: DID? = walletClient.walletDidPublic().orElse(null)
        return if(did != null) "did:" + did.method + ":" + did.did else null
    }

    override fun removeWallet(id: String) {

        val wallet = getWallet(id)
        if (wallet != null) {

            val walletId = wallet.walletId
            val walletName = wallet.walletName
            val accessToken = wallet.accessToken
            log.info("Remove Wallet: {}", walletName)

            super.removeWallet(walletId)

            val adminClient: AriesClient = adminClient()
            adminClient.multitenancyWalletRemove(
                walletId, RemoveWalletRequest.builder()
                    .walletKey(accessToken)
                    .build()
            )

            // Wait for the wallet to get removed
            Thread.sleep(500)
            while (adminClient.multitenancyWallets(walletName).get().isNotEmpty()) {
                Thread.sleep(500)
            }
        }
    }

    // -----------------------------------------------------------------------------------------------------------------
}
