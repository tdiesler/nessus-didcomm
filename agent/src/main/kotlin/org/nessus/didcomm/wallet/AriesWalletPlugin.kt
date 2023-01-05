package org.nessus.didcomm.wallet

import id.walt.crypto.KeyAlgorithm
import org.hyperledger.acy_py.generated.model.DID
import org.hyperledger.acy_py.generated.model.DIDCreate
import org.hyperledger.acy_py.generated.model.DIDCreateOptions
import org.hyperledger.aries.AriesClient
import org.hyperledger.aries.api.ledger.IndyLedgerRoles
import org.hyperledger.aries.api.ledger.RegisterNymFilter
import org.hyperledger.aries.api.multitenancy.CreateWalletRequest
import org.hyperledger.aries.api.multitenancy.RemoveWalletRequest
import org.hyperledger.aries.api.multitenancy.WalletDispatchType
import org.hyperledger.aries.api.wallet.WalletDIDCreate
import org.nessus.didcomm.agent.AriesAgentService
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidInfo
import org.nessus.didcomm.did.DidService.DEFAULT_KEY_ALGORITHM
import org.nessus.didcomm.service.WalletException

class AriesWalletPlugin: WalletPlugin() {

    override fun createWallet(config: Map<String, Any?>): NessusWallet {

        val walletAgent = WalletAgent.ACAPY
        val walletName = config["walletName"] as? String
        val walletType = config["walletType"] as? WalletType ?: WalletType.IN_MEMORY
        val walletKey = config["walletKey"] as? String ?: (walletName + "Key")
        val didMethod = config["didMethod"] as? DidMethod ?: DidMethod.KEY
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
            .walletType(toAriesWalletType(walletType))
            .build()
        val walletRecord = AriesAgentService.adminClient().multitenancyWalletCreate(walletRequest).get()
        val nessusWallet = NessusWallet(walletRecord.walletId, walletAgent, walletType, walletName, walletRecord.token)

        // Create a local DID for the wallet
        val walletClient = AriesAgentService.walletClient(nessusWallet)
        val didCreate = WalletDIDCreate.builder()
            .method(DIDCreate.MethodEnum.valueOf(didMethod.name))
            .build()
        val auxDid = walletClient.walletDidCreate(didCreate).get()
        val did = fromAriesDid(auxDid)!!
        log.info("{}: {}", walletName, did)

        if (publicDid || indyLedgerRole != null) {
            trusteeWallet ?: throw WalletException("LedgerRole $indyLedgerRole requires trusteeWallet")

            val trustee: AriesClient = AriesAgentService.walletClient(trusteeWallet)
            val trusteeName: String = trusteeWallet.walletName ?: trusteeWallet.walletId
            val nymResponse = trustee.ledgerRegisterNym(
                RegisterNymFilter.builder()
                    .did(did.id)
                    .verkey(did.verkey)
                    .role(indyLedgerRole)
                    .build()
            ).get()
            log.info("{} for {}: {}", trusteeName, walletName, nymResponse)

            // Set the public DID for the wallet
            walletClient.walletDidPublic(did.id)

            val didEndpoint = walletClient.walletGetDidEndpoint(did.id).get()
            log.info("{}: {}", walletName, didEndpoint)
        }

        return nessusWallet
    }

    override fun removeWallet(wallet: NessusWallet) {

        val walletId = wallet.walletId
        val walletName = wallet.walletName
        val accessToken = wallet.authToken
        log.info("Remove Wallet: {}", walletName)

        val adminClient: AriesClient = AriesAgentService.adminClient()
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

    override fun createDid(wallet: NessusWallet, method: DidMethod?, algorithm: KeyAlgorithm?, seed: String?): DidInfo {
        val walletClient = AriesAgentService.walletClient(wallet)
        val didOptions = DIDCreateOptions.builder()
            .keyType(DIDCreateOptions.KeyTypeEnum.valueOf(algorithm?.name ?: DEFAULT_KEY_ALGORITHM.name))
            .build()
        val didCreate = WalletDIDCreate.builder()
            .method(DIDCreate.MethodEnum.valueOf(method?.name ?: DidMethod.KEY.name))
            .options(didOptions)
            .build()
        val ariesDid = walletClient.walletDidCreate(didCreate).get()
        val nessusDid = fromAriesDid(ariesDid)!!
        return DidInfo(nessusDid, null, null)
    }

    override fun publicDid(wallet: NessusWallet): Did? {
        val walletClient = AriesAgentService.walletClient(wallet)
        return fromAriesDid(walletClient.walletDidPublic().orElse(null))
    }

    // -----------------------------------------------------------------------------------------------------------------

    private fun toAriesWalletType(type: WalletType): org.hyperledger.aries.api.multitenancy.WalletType {
        return org.hyperledger.aries.api.multitenancy.WalletType.valueOf(type.name)
    }

    private fun fromAriesDid(did: org.hyperledger.acy_py.generated.model.DID?): Did? {
        if (did == null) return null
        val method = DidMethod.valueOf(did.method.name)
        val algorithm = when(did.keyType) {
            DID.KeyTypeEnum.ED25519 -> KeyAlgorithm.EdDSA_Ed25519
            else -> throw IllegalStateException("Key algorithm not supported: ${did.keyType}")
        }
        return Did(did.did, method, algorithm, did.verkey)
    }
}