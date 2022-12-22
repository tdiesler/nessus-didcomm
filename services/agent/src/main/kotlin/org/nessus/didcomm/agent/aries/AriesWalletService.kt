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
import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.WalletException


class AriesWalletService : WalletService {

    private val log = KotlinLogging.logger {}

    override fun createWallet(config: Map<String, Any?>): NessusWallet {

        val walletName = assertConfigValue(config,"walletName") as String
        val auxWalletKey = getConfigValue(config,"walletKey")
        val walletKey = if (auxWalletKey != null) auxWalletKey as String else walletName + "Key"
        val selfRegister = getConfigValue(config, "selfRegister")
        val trusteeWallet = getConfigValue(config, "trusteeWallet")
        val ledgerRole = getConfigValue(config, "ledgerRole")
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
            if (selfRegister == false && trusteeWallet == null)
                throw WalletException("LedgerRole $indyLedgerRole requires selfRegister or trusteeWallet")

            // Create a local DID for the wallet
            val walletClient = AriesAgentService.walletClient(nessusWallet)
            val did: DID = walletClient.walletDidCreate(WalletDIDCreate.builder().build()).get()
            log.info("{}: {}", walletName, did)
            if (trusteeWallet != null) {
                val trustee: AriesClient = AriesAgentService.walletClient(trusteeWallet as NessusWallet)
                val trusteeName: String = trusteeWallet.walletName
                val nymResponse = trustee.ledgerRegisterNym(
                    RegisterNymFilter.builder()
                        .verkey(did.verkey)
                        .did(did.did)
                        .role(indyLedgerRole)
                        .build()
                ).get()
                log.info("{} for {}: {}", trusteeName, walletName, nymResponse)
            } else if (selfRegister == true) {
                // Register DID with the leder (out-of-band)
                selfRegisterWithDid(walletName, did.did, did.verkey, indyLedgerRole)
            }

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
        return walletClient.walletDidPublic().orElse(null)?.toString()
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

    private fun selfRegisterWithDid(alias: String, did: String, vkey: String, role: IndyLedgerRoles): Boolean {
        val host: String = System.getenv("INDY_WEBSERVER_HOSTNAME") ?: "localhost"
        val port: String = System.getenv("INDY_WEBSERVER_PORT") ?: "9000"
        return SelfRegistrationHandler(String.format("http://%s:%s/register", host, port))
            .registerWithDID(alias, did, vkey, role)
    }
}
