package org.nessus.didcomm.wallet

import id.walt.crypto.KeyAlgorithm
import id.walt.services.keystore.KeyStoreService
import mu.KotlinLogging
import org.hyperledger.acy_py.generated.model.DID
import org.hyperledger.acy_py.generated.model.DID.KeyTypeEnum
import org.hyperledger.acy_py.generated.model.DIDCreate
import org.hyperledger.acy_py.generated.model.DIDCreateOptions
import org.hyperledger.aries.AriesClient
import org.hyperledger.aries.api.ledger.IndyLedgerRoles
import org.hyperledger.aries.api.ledger.RegisterNymFilter
import org.hyperledger.aries.api.multitenancy.CreateWalletRequest
import org.hyperledger.aries.api.multitenancy.RemoveWalletRequest
import org.hyperledger.aries.api.multitenancy.WalletDispatchType
import org.hyperledger.aries.api.wallet.WalletDIDCreate
import org.nessus.didcomm.agent.AgentConfiguration
import org.nessus.didcomm.agent.AriesAgent
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.service.DEFAULT_KEY_ALGORITHM
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.service.WalletPlugin
import org.nessus.didcomm.service.WalletServicePlugin

class AriesWalletPlugin: WalletServicePlugin, WalletPlugin {
    val log = KotlinLogging.logger {}

    override fun createWallet(config: WalletConfig): Wallet {

        val agentType = AgentType.ACAPY
        val walletAlias = config.alias
        val storageType = config.storageType ?: StorageType.IN_MEMORY
        val walletKey = config.walletKey ?: (walletAlias + "Key")
        val publicDidMethod = config.publicDidMethod
        val ledgerRole = config.ledgerRole
        val trusteeWallet = config.trusteeWallet
        val walletOptions = config.walletOptions
        val indyLedgerRole = if (ledgerRole != null)
            IndyLedgerRoles.valueOf(ledgerRole.name.uppercase())
        else null

        val agentConfig = AgentConfiguration.agentConfiguration(walletOptions)
        val adminClient = AriesAgent.adminClient(agentConfig)

        val walletRequest = CreateWalletRequest.builder()
            .walletName(walletAlias)
            .walletKey(walletKey)
            .walletDispatchType(WalletDispatchType.DEFAULT)
            .walletType(storageType.toAriesWalletType())
            .build()
        val walletRecord = adminClient.multitenancyWalletCreate(walletRequest).get()
        val auxWallet = Wallet(
            walletRecord.walletId, walletAlias, agentType, storageType,
            authToken=walletRecord.token, options = walletOptions
        )

        var publicDid: Did? = null

        val wallet = if (publicDidMethod != null || indyLedgerRole != null) {
            checkNotNull(trusteeWallet) {"No trustee wallet"}

            // Create a local DID for the wallet
            val walletClient = AriesAgent.walletClient(auxWallet, agentConfig)
            val didMethod = publicDidMethod ?: DidMethod.SOV
            val didCreate = WalletDIDCreate.builder()
                .method(DIDCreate.MethodEnum.valueOf(didMethod.name))
                .build()

            publicDid = walletClient.walletDidCreate(didCreate).get().toNessusDid()

            val trusteeClient = AriesAgent.walletClient(trusteeWallet, agentConfig)
            val trusteeName: String = trusteeWallet.alias
            val nymResponse = trusteeClient.ledgerRegisterNym(
                RegisterNymFilter.builder()
                    .did(publicDid.id)
                    .verkey(publicDid.verkey!!)
                    .role(indyLedgerRole)
                    .build()
            ).get()
            log.info("{} for {}: {}", trusteeName, walletAlias, nymResponse)

            // Set the public DID for the wallet
            walletClient.walletDidPublic(publicDid.id)

            Wallet(auxWallet.id, walletAlias, agentType, storageType, auxWallet.authToken, auxWallet.options)
        } else auxWallet

        log.info("{}: did={} endpoint={}", walletAlias, publicDid?.qualified, wallet.endpointUrl)
        return wallet
    }

    override fun removeWallet(wallet: Wallet) {

        val walletId = wallet.id
        val walletAlias = wallet.alias
        val accessToken = wallet.authToken
        log.info("Remove Wallet: {}", walletAlias)

        val adminClient = wallet.adminClient() as AriesClient
        adminClient.multitenancyWalletRemove(
            walletId, RemoveWalletRequest.builder()
                .walletKey(accessToken)
                .build()
        )
    }

    override fun createDid(wallet: Wallet, method: DidMethod?, algorithm: KeyAlgorithm?, seed: String?): Did {
        val walletClient = wallet.walletClient() as AriesClient
        val didOptions = DIDCreateOptions.builder()
            .keyType((algorithm ?: DEFAULT_KEY_ALGORITHM).toAriesKeyType())
            .build()
        val didCreate = WalletDIDCreate.builder()
            .method(DIDCreate.MethodEnum.valueOf(method?.name ?: DidMethod.KEY.name))
            .options(didOptions)
            .build()
        val ariesDid = walletClient.walletDidCreate(didCreate).get()
        val nessusDid = ariesDid.toNessusDid()
        DidService.getService().registerWithKeyStore(nessusDid)
        return nessusDid
    }

    override fun publicDid(wallet: Wallet): Did? {
        val walletClient = wallet.walletClient() as AriesClient
        val ariesDid = walletClient.walletDidPublic().orElse(null) ?:
            return null
        val publicDid = ariesDid.toNessusDid()
        val keyStore = KeyStoreService.getService()
        keyStore.getKeyId(publicDid.qualified) ?: run {
            DidService.getService().registerWithKeyStore(publicDid)
        }
        return publicDid
    }

    override fun listDids(wallet: Wallet): List<Did> {
        val walletClient = wallet.walletClient() as AriesClient
        return walletClient.walletDid().get().map { it.toNessusDid() }
    }

    override fun removeConnections(wallet: Wallet) {
        val walletClient = wallet.walletClient() as AriesClient
        walletClient.connectionIds().forEach {
            walletClient.connectionsRemove( it )
        }
    }

// Private ---------------------------------------------------------------------------------------------------------

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
        else -> throw IllegalStateException("Key algorithm not supported: $this")
    }

    private fun StorageType.toAriesWalletType() = org.hyperledger.aries.api.multitenancy.WalletType.valueOf(this.name)
}