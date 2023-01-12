package org.nessus.didcomm.wallet

import id.walt.crypto.KeyAlgorithm
import id.walt.services.keystore.KeyStoreService
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
import org.nessus.didcomm.agent.AriesAgent
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.service.DEFAULT_KEY_ALGORITHM
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.service.PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1
import org.nessus.didcomm.service.WalletPlugin

class AriesWalletPlugin: WalletPlugin() {

    override fun createWallet(config: WalletConfig): Wallet {

        val walletAgent = WalletAgent.ACAPY
        val walletAlias = config.alias
        val walletType = config.walletType ?: WalletType.IN_MEMORY
        val walletKey = config.walletKey ?: walletAlias + "Key"
        val publicDidMethod = config.publicDidMethod
        val ledgerRole = config.ledgerRole
        val trusteeWallet = config.trusteeWallet
        val indyLedgerRole = if (ledgerRole != null)
            IndyLedgerRoles.valueOf(ledgerRole.name.uppercase())
        else null

        val adminClient = AriesAgent.adminClient()
        val walletRequest = CreateWalletRequest.builder()
            .walletName(walletAlias)
            .walletKey(walletKey)
            .walletDispatchType(WalletDispatchType.DEFAULT)
            .walletType(walletType.toAriesWalletType())
            .build()
        val walletRecord = adminClient.multitenancyWalletCreate(walletRequest).get()
        val auxWallet = Wallet(walletRecord.walletId, walletAlias, walletAgent, walletType, authToken=walletRecord.token)

        var publicDid: Did? = null

        val wallet = if (publicDidMethod != null || indyLedgerRole != null) {
            checkNotNull(trusteeWallet) {"No trustee wallet"}

            // Create a local DID for the wallet
            val walletClient = AriesAgent.walletClient(auxWallet)
            val didMethod = publicDidMethod ?: DidMethod.SOV
            val didCreate = WalletDIDCreate.builder()
                .method(DIDCreate.MethodEnum.valueOf(didMethod.name))
                .build()

            publicDid = walletClient.walletDidCreate(didCreate).get().toNessusDid()

            val trustee = AriesAgent.walletClient(trusteeWallet)
            val trusteeName: String = trusteeWallet.alias
            val nymResponse = trustee.ledgerRegisterNym(
                RegisterNymFilter.builder()
                    .did(publicDid.id)
                    .verkey(publicDid.verkey!!)
                    .role(indyLedgerRole)
                    .build()
            ).get()
            log.info("{} for {}: {}", trusteeName, walletAlias, nymResponse)

            // Set the public DID for the wallet
            walletClient.walletDidPublic(publicDid.id)

            val didEndpoint = walletClient.walletGetDidEndpoint(publicDid.id).get().endpoint
            Wallet(auxWallet.id, walletAlias, walletAgent, walletType, didEndpoint, auxWallet.authToken)
        } else auxWallet

        log.info("{}: did={} endpoint={}", walletAlias, publicDid?.qualified, wallet.endpointUrl)
        return wallet
    }

    override fun removeWallet(wallet: Wallet) {

        val walletId = wallet.id
        val walletAlias = wallet.alias
        val accessToken = wallet.authToken
        log.info("Remove Wallet: {}", walletAlias)

        val adminClient: AriesClient = AriesAgent.adminClient()
        adminClient.multitenancyWalletRemove(
            walletId, RemoveWalletRequest.builder()
                .walletKey(accessToken)
                .build()
        )

        // Wait for the wallet to get removed
        Thread.sleep(1000)
        while (adminClient.multitenancyWallets(walletAlias).get().isNotEmpty()) {
            Thread.sleep(500)
        }
    }

    override fun createDid(wallet: Wallet, method: DidMethod?, algorithm: KeyAlgorithm?, seed: String?): Did {
        val walletClient = AriesAgent.walletClient(wallet)
        val didOptions = DIDCreateOptions.builder()
            .keyType((algorithm ?: DEFAULT_KEY_ALGORITHM).toAriesKeyType())
            .build()
        val didCreate = WalletDIDCreate.builder()
            .method(DIDCreate.MethodEnum.valueOf(method?.name ?: DidMethod.KEY.name))
            .options(didOptions)
            .build()
        val ariesDid = walletClient.walletDidCreate(didCreate).get()
        val nessusDid = ariesDid.toNessusDid()
        DidService.getService().registerDidVerkey(nessusDid)
        return nessusDid
    }

    override fun publicDid(wallet: Wallet): Did? {
        val walletClient = AriesAgent.walletClient(wallet)
        val ariesDid = walletClient.walletDidPublic().orElse(null) ?:
            return null
        val publicDid = ariesDid.toNessusDid()
        val keyStore = KeyStoreService.getService()
        keyStore.getKeyId(publicDid.qualified) ?: run {
            DidService.getService().registerDidVerkey(publicDid)
        }
        return publicDid
    }

    override fun listSupportedProtocols(): List<String> {
        return listOf(PROTOCOL_URI_RFC0434_OUT_OF_BAND_V1_1.name)
    }

    override fun listDids(wallet: Wallet): List<Did> {
        val walletClient = AriesAgent.walletClient(wallet)
        return walletClient.walletDid().get().map { it.toNessusDid() }
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

    private fun WalletType.toAriesWalletType() = org.hyperledger.aries.api.multitenancy.WalletType.valueOf(this.name)
}