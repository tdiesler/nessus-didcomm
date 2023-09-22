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
package org.nessus.didcomm.json.model

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.StorageType
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.model.Wallet.WalletConfig
import org.nessus.didcomm.model.WalletRole

@Serializable
data class WalletData(
    val id: String? = null,
    val alias: String? = null,
    val agentType: AgentType? = null,
    val storageType: StorageType? = null,
    val walletRole: WalletRole? = null,
    val endpointUrl: String? = null,
    val routingKeys: List<String>? = null,
    val options: Map<String, String>? = null,
) {

    companion object {

        @JvmStatic
        fun fromJson(json: String): WalletData = Json.decodeFromString<WalletData>(json)

        @JvmStatic
        fun fromWallet(wallet: Wallet): WalletData {
            return WalletData(
                id = wallet.id,
                alias = wallet.alias,
                agentType = wallet.agentType,
                storageType = wallet.storageType,
                walletRole = wallet.walletRole,
                endpointUrl = wallet.endpointUrl,
                routingKeys = wallet.routingKeys?.toList(),
                options = wallet.options?.toMap(),
            )
        }
    }

    fun toWalletConfig(): WalletConfig {
        checkNotNull(alias) { "No name" }
        return WalletConfig(
            alias,
            agentType,
            storageType,
            walletRole,
            endpointUrl,
            routingKeys,
            options,
        )
    }

    fun toJson() = Json.encodeToString(this)
}
