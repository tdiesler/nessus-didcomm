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

import com.google.gson.FieldNamingPolicy
import com.google.gson.Gson
import com.google.gson.GsonBuilder
import mu.KotlinLogging
import org.hyperledger.aries.api.connection.ConnectionRecord
import org.hyperledger.aries.api.multitenancy.CreateWalletTokenRequest
import org.nessus.didcomm.agent.AriesAgentService
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.agent.AriesClientFactory
import org.nessus.didcomm.service.ServiceRegistry.walletService
import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.WalletAgent
import org.nessus.didcomm.wallet.WalletType
import org.slf4j.event.Level

const val GOVERNMENT = "Government"
const val FABER = "Faber"
const val ALICE = "Alice"

abstract class AbstractIntegrationTest {

    val log = KotlinLogging.logger {}

    val gson: Gson = GsonBuilder()
        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
        .create()
    val prettyGson: Gson = GsonBuilder()
        .setFieldNamingPolicy(FieldNamingPolicy.LOWER_CASE_WITH_UNDERSCORES)
        .setPrettyPrinting()
        .create()

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
