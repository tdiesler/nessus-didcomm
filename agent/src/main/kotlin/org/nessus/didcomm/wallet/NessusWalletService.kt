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
package org.nessus.didcomm.wallet

import mu.KotlinLogging
import org.hyperledger.acy_py.generated.model.DIDCreate
import org.hyperledger.aries.AriesClient
import org.hyperledger.aries.api.ledger.IndyLedgerRoles
import org.hyperledger.aries.api.ledger.RegisterNymFilter
import org.hyperledger.aries.api.multitenancy.CreateWalletRequest
import org.hyperledger.aries.api.multitenancy.RemoveWalletRequest
import org.hyperledger.aries.api.multitenancy.WalletDispatchType
import org.hyperledger.aries.api.wallet.WalletDIDCreate
import org.nessus.didcomm.DID
import org.nessus.didcomm.KeyType
import org.nessus.didcomm.agent.AriesAgentService
import org.nessus.didcomm.agent.AriesAgentService.Companion.adminClient
import org.nessus.didcomm.service.WalletException
import org.nessus.didcomm.service.WalletService

class NessusWalletService : WalletService {

    private val log = KotlinLogging.logger {}

    private val plugins = mapOf(
        WalletType.INDY to AriesWalletPlugin(),
        WalletType.IN_MEMORY to AriesWalletPlugin())

    override fun createWallet(config: Map<String, Any?>): NessusWallet {

        val walletType = config["walletType"] as? WalletType ?: WalletType.IN_MEMORY
        val nessusWallet = walletPlugin(walletType).createWallet(config)
        putWallet(nessusWallet)
        return nessusWallet
    }

    override fun publicDid(wallet: NessusWallet): DID? {
        return walletPlugin(wallet.walletType).publicDid(wallet)
    }

    override fun removeWallet(id: String) {

        val wallet = getWallet(id)
        if (wallet != null) {

            val walletId = wallet.walletId
            val walletName = wallet.walletName
            val accessToken = wallet.authToken
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

    private fun walletPlugin(walletType: WalletType): WalletPlugin {
        return plugins[walletType] as WalletPlugin
    }
}

private abstract class WalletPlugin {

    val log = KotlinLogging.logger {}

    abstract fun createWallet(config: Map<String, Any?>): NessusWallet

    abstract fun publicDid(wallet: NessusWallet): DID?
}

private class AriesWalletPlugin: WalletPlugin() {

    override fun createWallet(config: Map<String, Any?>): NessusWallet {

        val walletName = config["walletName"] as? String
        val walletType = config["walletType"] as? WalletType ?: WalletType.IN_MEMORY
        val walletKey = config["walletKey"] as? String ?: (walletName + "Key")
        val didMethod = config["didMethod"] as? DIDMethod ?: DIDMethod.KEY
        val trusteeWallet = config["trusteeWallet"] as? NessusWallet
        val ledgerRole = config["ledgerRole"] as? LedgerRole
        val publicDid = config["publicDid"] as? Boolean ?: false
        val indyLedgerRole = if (ledgerRole != null)
            IndyLedgerRoles.valueOf(ledgerRole.name.uppercase())
        else null

        val walletRequest = CreateWalletRequest.builder()
            .walletName(walletName)
            .walletKey(walletKey)
            .walletDispatchType(WalletDispatchType.DEFAULT)
            .walletType(walletTypeAdaptor(walletType))
            .build()
        val walletRecord = adminClient().multitenancyWalletCreate(walletRequest).get()
        val nessusWallet = NessusWallet(walletRecord.walletId, walletType, walletName, walletRecord.token)
        log.info("{}: {}", walletName, nessusWallet)

        // Create a local DID for the wallet
        val walletClient = AriesAgentService.walletClient(nessusWallet)
        val didCreate = WalletDIDCreate.builder()
            .method(DIDCreate.MethodEnum.valueOf(didMethod.name))
            .build()
        val auxDid = walletClient.walletDidCreate(didCreate).get()
        val did = didAdaptor(auxDid)!!
        log.info("{}: {}", walletName, did)

        if (publicDid || indyLedgerRole != null) {
            trusteeWallet ?: throw WalletException("LedgerRole $indyLedgerRole requires trusteeWallet")

            val trustee: AriesClient = AriesAgentService.walletClient(trusteeWallet)
            val trusteeName: String = trusteeWallet.walletName ?: trusteeWallet.walletId
            val nymResponse = trustee.ledgerRegisterNym(
                RegisterNymFilter.builder()
                    .did(did.did)
                    .verkey(did.verkey)
                    .role(indyLedgerRole)
                    .build()
            ).get()
            log.info("{} for {}: {}", trusteeName, walletName, nymResponse)

            // Set the public DID for the wallet
            walletClient.walletDidPublic(did.did)

            val didEndpoint = walletClient.walletGetDidEndpoint(did.did).get()
            log.info("{}: {}", walletName, didEndpoint)
        }

        return nessusWallet
    }

    override fun publicDid(wallet: NessusWallet): DID? {
        val walletClient = AriesAgentService.walletClient(wallet)
        return didAdaptor(walletClient.walletDidPublic().orElse(null))
    }

    // -----------------------------------------------------------------------------------------------------------------

    fun walletTypeAdaptor(type: WalletType): org.hyperledger.aries.api.multitenancy.WalletType {
        return org.hyperledger.aries.api.multitenancy.WalletType.valueOf(type.name)
    }

    fun didAdaptor(did: org.hyperledger.acy_py.generated.model.DID?): DID? {
        if (did == null) return null
        return DID(did.did, DIDMethod.valueOf(did.method.name), KeyType.valueOf(did.keyType.name), did.verkey)
    }
}

private class NessusWalletPlugin: WalletPlugin() {

    override fun createWallet(config: Map<String, Any?>): NessusWallet {
        TODO("Not yet implemented")
    }

    override fun publicDid(wallet: NessusWallet): DID? {
        TODO("Not yet implemented")
    }
}