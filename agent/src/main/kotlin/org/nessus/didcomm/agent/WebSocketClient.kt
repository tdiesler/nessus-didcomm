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
package org.nessus.didcomm.agent

import mu.KotlinLogging
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.WebSocket
import org.nessus.didcomm.agent.AgentConfiguration.Companion.agentConfiguration
import org.nessus.didcomm.wallet.AcapyWallet

/**
 * Creates and maintains a WebSocket connection (optionally) on behalf of a given wallet.
 */
class WebSocketClient(val wallet: AcapyWallet, val listener: WebSocketListener) {
    val log = KotlinLogging.logger {}

    private var webSocket: WebSocket? = null

    fun openWebSocket() = apply {
        val config = agentConfiguration(wallet.options)
        val request: Request = Request.Builder()
            .url(wallet.getWebSocketUrl() as String)
            .header("X-API-Key", config.apiKey)
            .header("Authorization", "Bearer " + wallet.authToken)
            .build()
        val httpClient = OkHttpClient()
        webSocket = httpClient.newWebSocket(request, listener)
    }

    fun closeWebSocket() {
        if (webSocket != null) {
            webSocket!!.close(1001, null)
            webSocket = null
        }
    }
}
