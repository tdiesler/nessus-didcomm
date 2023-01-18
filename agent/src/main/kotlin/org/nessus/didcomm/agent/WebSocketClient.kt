package org.nessus.didcomm.agent

import mu.KotlinLogging
import okhttp3.OkHttpClient
import okhttp3.Request
import okhttp3.WebSocket
import org.nessus.didcomm.agent.AgentConfiguration.Companion.agentConfiguration
import org.nessus.didcomm.wallet.Wallet

/**
 * Creates and maintains a WebSocket connection (optionally) on behalf of a given wallet.
 */
class WebSocketClient(val wallet: Wallet, val listener: WebSocketListener) {
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