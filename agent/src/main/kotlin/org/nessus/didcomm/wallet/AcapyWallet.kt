/*-
 * #%L
 * Nessus DIDComm :: Core
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

import org.nessus.didcomm.agent.AgentConfiguration.Companion.agentConfiguration
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.agent.AriesClientFactory
import org.nessus.didcomm.agent.WebSocketClient
import org.nessus.didcomm.agent.WebSocketEvent
import org.nessus.didcomm.agent.WebSocketListener
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.StorageType
import org.nessus.didcomm.model.Wallet
import org.slf4j.event.Level

class AcapyWallet(
    id: String,
    name: String,
    agentType: AgentType,
    storageType: StorageType,
    endpointUrl: String,
    options: Map<String, Any> = mapOf(),
    val authToken: String? = null,
): Wallet(id, name, agentType, storageType, endpointUrl, options) {

    @Transient
    private val interceptorLogLevel = Level.INFO

    @Transient
    private var webSocketClient: WebSocketClient? = null

    override val walletPlugin get() = AcapyWalletPlugin()

    // [TODO] Abstract the Agent client
    fun adminClient(): AriesClient? {
        return if (agentType == AgentType.ACAPY) {
            val config = agentConfiguration(options)
            AriesClientFactory.adminClient(config, level = interceptorLogLevel)
        } else null
    }

    // [TODO] Abstract the Wallet client
    fun walletClient(): AriesClient? {
        return if (agentType == AgentType.ACAPY) {
            val config = agentConfiguration(options)
            AriesClientFactory.walletClient(this, config, level = interceptorLogLevel)
        } else null
    }

    fun getWebSocketUrl(): String? {
        return if (agentType == AgentType.ACAPY) {
            agentConfiguration(options).wsUrl
        } else null
    }

    fun openWebSocket(eventListener: (wse: WebSocketEvent) -> Unit) {
        val webSocketListener = WebSocketListener(this, eventListener)
        webSocketClient = WebSocketClient(this, webSocketListener).openWebSocket()
    }

    fun closeWebSocket() {
        webSocketClient?.closeWebSocket()
        webSocketClient = null
    }

    fun closeWallet() {
        closeWebSocket()
    }

    override fun removeConnections() {
        return walletService.removeConnections(this)
    }

    override fun toString(): String {
        var redactedToken: String? = null
        if (authToken != null)
            redactedToken = authToken.substring(0, 6) + "..." + authToken.substring(authToken.length - 6)
        return "Wallet(id='$id', agent=$agentType, type=$storageType, alias=$name, endpointUrl=$endpointUrl, options=$options, authToken=$redactedToken)"
    }

    // Private ---------------------------------------------------------------------------------------------------------

}

