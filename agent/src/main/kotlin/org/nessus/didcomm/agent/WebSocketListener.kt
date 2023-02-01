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

import com.google.gson.JsonObject
import com.google.gson.JsonSyntaxException
import mu.KotlinLogging
import okhttp3.Response
import okhttp3.WebSocket
import org.hyperledger.aries.BaseClient
import org.hyperledger.aries.webhook.EventType
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.wallet.Wallet
import java.util.concurrent.locks.Lock
import java.util.concurrent.locks.ReentrantLock

/**
 * An abstract WebSocketListener that gives access to the current state of the connection
 * as well as the stream of events seen by this listener.
 *
 * By default, incoming events are simply logged and there is no event recording. An extension
 * of this WebSocketListener would implement the various `handleFoo` methods and process events
 * as needed by the application.
 *
 * This class can also start/stop recording of incoming events by event type.
 * These recorded events can later be retrieved by the application.
 *
 * Note, there is currently no resource limit on the volume of recorded events. This must
 * be taken care of by the application doing the recording.
 */
class WebSocketListener(val wallet: Wallet, private val eventListener: (wse: WebSocketEvent) -> Unit) : okhttp3.WebSocketListener() {
    val log = KotlinLogging.logger {}

    enum class WebSocketState {
        NEW, OPEN, CLOSING, CLOSED
    }

    private var webSocketState = WebSocketState.NEW
    private val accessLock: Lock = ReentrantLock()

    override fun onOpen(webSocket: WebSocket, response: Response) {
        log.info("{}: WebSocket Open: {}", wallet.name, response)
        webSocketState = WebSocketState.OPEN
    }

    override fun onClosing(webSocket: WebSocket, code: Int, reason: String) {
        log.info("{}: WebSocket Closing: {} {}", wallet.name, code, reason)
        webSocketState = WebSocketState.CLOSING
    }

    override fun onClosed(webSocket: WebSocket, code: Int, reason: String) {
        log.info("{}: WebSocket Closed: {} {}", wallet.name, code, reason)
        accessLock.lock()
        try {
            webSocketState = WebSocketState.CLOSED
        } finally {
            accessLock.unlock()
        }
    }

    override fun onFailure(webSocket: WebSocket, t: Throwable, response: Response?) {
        val message = response?.message ?: t.message!!
        if ("Socket closed" != message)
            log.error("[${wallet.name}] Failure: $message", t)
    }

    override fun onMessage(webSocket: WebSocket, text: String) {
        try {
            val json = gson.fromJson(text, JsonObject::class.java)
            val walletId = if (json.has("wallet_id")) json["wallet_id"].asString else null
            val payload = if (json.has("payload")) json["payload"].toString() else BaseClient.EMPTY_JSON
            val topic = json["topic"].asString

            // Drop ws ping messages, not to be confused with aca-py ping message
            // https://datatracker.ietf.org/doc/html/rfc6455#section-5.5.2
            if (notWsPing(topic, payload)) {
                val event = WebSocketEvent(walletId, topic, payload)
                if (walletId == null) {
                    log.info { "${wallet.name} Untargeted Event: $text" }
                } else if (walletId == wallet.id) {
                    eventListener.invoke(event)
                }
            }
        } catch (ex: JsonSyntaxException) {
            log.error("JsonSyntaxException", ex)
        }
    }

    private fun notWsPing(topic: String, payload: String): Boolean {
        return !(EventType.PING.topicEquals(topic) && BaseClient.EMPTY_JSON == payload)
    }
}

data class WebSocketEvent(
    val walletId: String?,
    val topic: String,
    val payload: String
)
