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
package org.nessus.didcomm.service

import org.nessus.didcomm.util.encodeJson
import io.undertow.Undertow
import io.undertow.server.HttpHandler
import io.undertow.server.HttpServerExchange
import io.undertow.util.Headers
import io.undertow.util.Methods
import mu.KotlinLogging
import org.nessus.didcomm.model.EndpointMessage
import org.nessus.didcomm.util.JSON_MIME_TYPE
import java.io.PrintWriter
import java.io.StringWriter
import java.net.HttpURLConnection.HTTP_INTERNAL_ERROR
import java.net.HttpURLConnection.HTTP_OK
import java.net.URL


interface HttpEndpointHandle: AutoCloseable

class HttpEndpointService: EndpointService<HttpEndpointHandle>() {
    private val log = KotlinLogging.logger {}

    private val dashboard get() = DashboardService.getService()
    private val receiverService get() = MessageReceiverService.getService()

    companion object {
        fun getRequestHeadersAsMap(exchange: HttpServerExchange): Map<String, Any?> {
            val headersMap = mutableMapOf<String, Any?>()
            val requestHeaders = exchange.requestHeaders
            for (key in requestHeaders.headerNames) {
                val values = requestHeaders[key]
                if (values != null && !values.isEmpty()) {
                    // For simplicity, we assume first value only
                    headersMap[key.toString()] = values.first()
                }
            }
            return headersMap
        }

        fun getRequestBodyAsString(exchange: HttpServerExchange): String {
            val bodyBuilder = StringBuilder() // ;-)
            exchange.requestReceiver.receiveFullString { _, body -> bodyBuilder.append(body) }
            return bodyBuilder.toString()
        }
    }

    override fun startEndpoint(endpointUrl: String, dispatcher: MessageReceiver?): HttpEndpointHandle {
        log.info("Starting Http endpoint on: $endpointUrl")

        // Define the HTTP handler to handle incoming requests
        val handler = HttpHandler { exchange ->
            when(val httpMethod = exchange.requestMethod) {
                Methods.GET -> dashboard.processHttpGet(exchange)
                Methods.POST -> processHttpPost(exchange, dispatcher)
                else -> throw IllegalStateException("Unsupported HTTP method: $httpMethod")
            }
        }

        // Create an Undertow server and configure it to listen on a specific host and port
        val server = Undertow.builder()
            .addHttpListener(URL(endpointUrl).port, "0.0.0.0")
            .setHandler(handler)
            .build()

        // Start the server
        server.start()

        return object : HttpEndpointHandle {
            override fun close() {
                server.stop()
            }
        }
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun processHttpPost(exchange: HttpServerExchange, messageReceiver: MessageReceiver?) {
        val headers = getRequestHeadersAsMap(exchange)
        val body = getRequestBodyAsString(exchange)
        runCatching {
            val epm = EndpointMessage.Builder(body, headers)
                .inbound()
                .build()
            (messageReceiver ?: receiverService).invoke(epm)

            exchange.statusCode = HTTP_OK
            exchange.responseHeaders.put(Headers.CONTENT_TYPE, JSON_MIME_TYPE)
            exchange.responseSender.send("{}")
        }.onFailure { th ->
            exchange.statusCode = HTTP_INTERNAL_ERROR
            exchange.responseHeaders.put(Headers.CONTENT_TYPE, JSON_MIME_TYPE)
            val sw = StringWriter()
            th.printStackTrace(PrintWriter(sw))
            val traceLines = "$sw".lines().map { it.trim() }.find { it.isNotEmpty() }
            exchange.responseSender.send(mapOf(
                "msg" to th.message,
                "trace" to traceLines,
            ).encodeJson())
            log.error(th) { th.message }
        }
    }
}