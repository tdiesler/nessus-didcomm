/*-
 * #%L
 * Nessus DIDComm :: Agent
 * %%
 * Copyright (C) 2022 - 2023 Nessus
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

import id.walt.services.keystore.KeyStoreService
import mu.KotlinLogging
import org.hyperledger.acy_py.generated.model.DID
import org.hyperledger.acy_py.generated.model.DID.KeyTypeEnum
import org.hyperledger.acy_py.generated.model.DIDCreate
import org.hyperledger.acy_py.generated.model.DIDCreateOptions
import org.hyperledger.aries.api.connection.ConnectionTheirRole
import org.hyperledger.aries.api.ledger.IndyLedgerRoles
import org.hyperledger.aries.api.ledger.RegisterNymFilter
import org.hyperledger.aries.api.multitenancy.CreateWalletRequest
import org.hyperledger.aries.api.multitenancy.RemoveWalletRequest
import org.hyperledger.aries.api.multitenancy.WalletDispatchType
import org.hyperledger.aries.api.wallet.WalletDIDCreate
import org.nessus.didcomm.agent.AgentConfiguration.Companion.agentConfiguration
import org.nessus.didcomm.agent.AriesAgent
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.did.DEFAULT_KEY_ALGORITHM
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.did.KeyAlgorithm
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.ConnectionRole
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.StorageType
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.ModelService
import org.nessus.didcomm.service.NessusDidService
import org.nessus.didcomm.service.WalletPlugin

fun ConnectionTheirRole.toConnectionRole(): ConnectionRole {
    return ConnectionRole.valueOf(this.name.uppercase())
}

fun org.hyperledger.aries.api.connection.ConnectionState.toConnectionState(): ConnectionState {
    return ConnectionState.valueOf(this.name.uppercase())
}

class AcapyWalletPlugin: WalletPlugin {
    val log = KotlinLogging.logger {}

    val modelService get() = ModelService.getService()

    override fun createWallet(config: WalletConfig): Wallet {

        val agentType = AgentType.ACAPY
        val walletName = config.name
        val storageType = config.storageType ?: StorageType.IN_MEMORY
        val walletKey = config.walletKey ?: (walletName + "Key")
        val publicDidMethod = config.publicDidMethod
        val ledgerRole = config.ledgerRole
        val trusteeWallet = config.trusteeWallet
        val options = config.options
        val indyLedgerRole = if (ledgerRole != null)
            IndyLedgerRoles.valueOf(ledgerRole.name.uppercase())
        else null

        val agentConfig = agentConfiguration(options)
        val adminClient = AriesAgent.adminClient(agentConfig)

        val walletRequest = CreateWalletRequest.builder()
            .walletName(walletName)
            .walletKey(walletKey)
            .walletDispatchType(WalletDispatchType.DEFAULT)
            .walletType(storageType.toAriesWalletType())
            .build()
        val walletRecord = adminClient.multitenancyWalletCreate(walletRequest).get()
        val auxWallet = AcapyWallet(
            walletRecord.walletId, walletName, agentType,
            storageType, agentConfig.userUrl,
            options=options, authToken=walletRecord.token
        )

        var publicDid: Did? = null

        val wallet = if (publicDidMethod != null || indyLedgerRole != null) {
            checkNotNull(trusteeWallet) {"No trustee wallet"}

            // Create a local DID for the wallet
            val walletClient = AriesAgent.walletClient(auxWallet, agentConfig)
            publicDid = createDidInternal(walletClient, publicDidMethod ?: DidMethod.SOV)

            val trusteeClient = AriesAgent.walletClient(trusteeWallet, agentConfig)
            val trusteeName: String = trusteeWallet.name
            val nymResponse = trusteeClient.ledgerRegisterNym(
                RegisterNymFilter.builder()
                    .did(publicDid.id)
                    .verkey(publicDid.verkey)
                    .role(indyLedgerRole)
                    .build()
            ).get()
            log.info("{} for {}: {}", trusteeName, walletName, nymResponse)

            // Set the public DID for the wallet
            walletClient.walletDidPublic(publicDid.id)
            val endpointUrl = walletClient.walletGetDidEndpoint(publicDid.id).get().endpoint

            AcapyWallet(
                auxWallet.id,
                walletName,
                agentType,
                storageType,
                endpointUrl,
                auxWallet.options,
                auxWallet.authToken
            )
        } else auxWallet

        log.info("{}: did={} endpoint={}", walletName, publicDid?.uri, wallet.endpointUrl)
        return wallet
    }

    override fun removeWallet(wallet: Wallet) {
        require(wallet is AcapyWallet) { "Not an AcapyWallet" }

        val walletId = wallet.id
        val walletName = wallet.name
        val accessToken = wallet.authToken
        log.info("Remove Wallet: {}", walletName)

        val adminClient = wallet.adminClient() as AriesClient
        adminClient.multitenancyWalletRemove(
            walletId, RemoveWalletRequest.builder()
                .walletKey(accessToken)
                .build()
        )
    }

    override fun createDid(wallet: Wallet, method: DidMethod?, keyAlias: String?): Did {
        require(keyAlias == null) { "keyAlias not supported" }
        return createDidInternal(walletClient(wallet), method)
    }

    override fun publicDid(wallet: Wallet): Did? {
        val walletClient = walletClient(wallet)
        val ariesDid = walletClient.walletDidPublic().orElse(null) ?:
            return null
        val publicDid = ariesDid.toNessusDid()
        val keyStore = KeyStoreService.getService()
        keyStore.getKeyId(publicDid.uri) ?: run {
            NessusDidService.getService().importDid(publicDid)
        }
        return publicDid
    }

    override fun removeConnections(wallet: Wallet) {
        val walletClient = walletClient(wallet)
        walletClient.connectionIds().forEach {
            walletClient.connectionsRemove( it )
        }
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun createDidInternal(walletClient: AriesClient, method: DidMethod?): Did {
        val didOptions = DIDCreateOptions.builder()
            .keyType(DEFAULT_KEY_ALGORITHM.toAriesKeyType())
            .build()
        val didCreate = WalletDIDCreate.builder()
            .method(DIDCreate.MethodEnum.valueOf(method?.name ?: DidMethod.KEY.name))
            .options(didOptions)
            .build()
        val ariesDid = walletClient.walletDidCreate(didCreate).get()
        val nessusDid = ariesDid.toNessusDid()
        NessusDidService.getService().importDid(nessusDid)
        return nessusDid
    }

    private fun walletClient(wallet: Wallet): AriesClient {
        require(wallet is AcapyWallet) { "Not an AcapyWallet" }
        return wallet.walletClient() as AriesClient
    }

    private fun DID.toNessusDid(): Did = run {
        val method = DidMethod.valueOf(this.method.name)
        val algorithm = this.keyType.toKeyAlgorithm()
        Did(this.did, method, algorithm, this.verkey)
    }

    private fun KeyTypeEnum.toKeyAlgorithm() = when(this) {
        KeyTypeEnum.ED25519 -> KeyAlgorithm.EdDSA_Ed25519
        else -> throw IllegalStateException("Key type not supported: $this")
    }

    private fun KeyAlgorithm.toAriesKeyType() = when(this) {
        KeyAlgorithm.EdDSA_Ed25519 -> DIDCreateOptions.KeyTypeEnum.ED25519
        // else -> throw IllegalStateException("Key algorithm not supported: $this")
    }

    private fun StorageType.toAriesWalletType() = org.hyperledger.aries.api.multitenancy.WalletType.valueOf(this.name)
}
