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

import id.walt.servicematrix.ServiceMatrix
import id.walt.services.crypto.CryptoService
import id.walt.services.keystore.KeyStoreService
import mu.KotlinLogging
import org.hyperledger.aries.api.connection.ConnectionRecord
import org.hyperledger.aries.api.multitenancy.CreateWalletTokenRequest
import org.junit.jupiter.api.BeforeAll
import org.nessus.didcomm.agent.AriesAgentService
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.agent.AriesClientFactory
import org.nessus.didcomm.crypto.NessusCryptoService
import org.nessus.didcomm.service.ServiceRegistry.walletService
import org.nessus.didcomm.util.encodeHex
import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.WalletAgent
import org.nessus.didcomm.wallet.WalletType
import org.slf4j.event.Level

object Government {
    val name = "Government"
    val seed = "000000000000000000000000Trustee1"
    val seedHex = seed.toByteArray().encodeHex()
    val verkey = "GJ1SzoWzavQYfNL9XkaJdrQejfztN4XqdsiV4ct3LXKL"
    val didkey = "did:key:z6MkukGVb3mRvTu1msArDKY9UwxeZFGjmwnCKtdQttr4Fk6i"
}
object Faber {
    val name = "Faber"
    val seed = "00000000000000000000000Endorser1"
    val seedHex = seed.toByteArray().encodeHex()
    val verkey = "CcokUqV7WkojBLxYm7gxRzsWk3q4SE8eVMmEXoYjyvKw"
    val didkey = "did:key:z6Mkr54o55jYrJJCHqoFSgeoH6RWZd6ur7P1BNgAN5Wku97K"
}
object Alice {
    val name = "Alice"
    val seed = "00000000000000000000000000Alice1"
    val seedHex = seed.toByteArray().encodeHex()
    val verkey = "ESqH2YuYRRXMMfg5qQh1A23nzBaUvAMCEXLtBr2uDHbY"
    val didkey = "did:key:z6Mksu6Kco9yky1pUAWnWyer17bnokrLL3bYvYFp27zv8WNv"
}

const val RESOURCES_PATH: String = "src/test/resources"

abstract class AbstractIntegrationTest {

    val log = KotlinLogging.logger {}

    companion object {
        @BeforeAll
        @JvmStatic
        internal fun beforeAll() {
            ServiceMatrix("${RESOURCES_PATH}/service-matrix.properties")
        }
    }

    val cryptoService = CryptoService.getService().implementation as NessusCryptoService
    val keyStore = KeyStoreService.getService()

    fun adminClient(): AriesClient {
        return AriesClientFactory.adminClient(level=Level.INFO)
    }

    fun walletClient(wallet: NessusWallet): AriesClient {
        return AriesClientFactory.walletClient(wallet, level=Level.INFO)
    }

    fun getWalletByName(walletName: String): NessusWallet? {
        var wallet = walletService().getWalletByName(walletName)
        if (wallet == null) {
            val adminClient = AriesAgentService.adminClient()
            val walletRecord = adminClient.multitenancyWallets(walletName).get().firstOrNull()
            if (walletRecord != null) {
                val walletAgent = WalletAgent.ACAPY
                val walletId = walletRecord.walletId
                val walletType = WalletType.valueOf(walletRecord.settings.walletType.toString())
                val tokReq = CreateWalletTokenRequest.builder().build()
                val tokRes = adminClient.multitenancyWalletToken(walletId, tokReq).get()
                wallet = NessusWallet(walletId, walletAgent, walletType, walletName, tokRes.token)
            }
        }
        return wallet
    }

    fun removeWallet(wallet: NessusWallet?) {
        if (wallet != null) {
            walletService().removeWallet(wallet.walletId)
        }
    }

    fun awaitConnectionRecord(client: AriesClient, predicate: (cr: ConnectionRecord) -> Boolean): ConnectionRecord? {
        var retries = 10
        var maybeConnection = client.connections().get().firstOrNull { predicate(it) }
        while (maybeConnection == null && (0 < retries--)) {
            Thread.sleep(500)
            maybeConnection = client.connections().get().firstOrNull { predicate(it) }
        }
        return maybeConnection
    }
}
