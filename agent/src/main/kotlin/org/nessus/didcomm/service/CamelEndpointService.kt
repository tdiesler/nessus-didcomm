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

import mu.KotlinLogging
import org.apache.camel.CamelContext
import org.apache.camel.Exchange
import org.apache.camel.builder.RouteBuilder
import org.apache.camel.impl.DefaultCamelContext
import org.nessus.didcomm.model.EndpointMessage
import org.nessus.didcomm.util.encodeJson
import java.io.PrintWriter
import java.io.StringWriter
import java.net.HttpURLConnection.HTTP_INTERNAL_ERROR
import java.net.HttpURLConnection.HTTP_OK

class CamelEndpointService: EndpointService<CamelContext>() {
    private val log = KotlinLogging.logger {}

    private val dashboard get() = DashboardService.getService()
    private val receiverService get() = MessageReceiverService.getService()

    override fun startEndpoint(endpointUrl: String, dispatcher: MessageReceiver?): CamelContext {
        log.info("Starting Camel endpoint on: $endpointUrl")
        val camelctx: CamelContext = DefaultCamelContext()
        camelctx.addRoutes(object: RouteBuilder(camelctx) {
            override fun configure() {
                from("undertow:$endpointUrl?matchOnUriPrefix=true")
                    .process { exchange ->
                        val headers = exchange.message.headers
                        when(val httpMethod = headers["CamelHttpMethod"]) {
                            "GET" -> dashboard.processHttpGet(exchange)
                            "POST" -> processDidCommMessage(exchange, dispatcher)
                            else -> throw IllegalStateException("Unsupported HTTP method: $httpMethod")
                        }
                    }
            }
        })
        camelctx.start()
        return camelctx
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun processDidCommMessage(exchange: Exchange, messageReceiver: MessageReceiver?) {
        val headers = exchange.message.headers
        val body = exchange.message.getBody(String::class.java)
        checkNotNull(body) { "No message body" }
        runCatching {
            val epm = EndpointMessage.Builder(body, headers)
                .inbound()
                .build()
            (messageReceiver ?: receiverService).invoke(epm)
            headers[Exchange.HTTP_RESPONSE_CODE] = HTTP_OK
            headers[Exchange.CONTENT_TYPE] = "application/json"
            exchange.message.body = "{}"
        }.onFailure { th ->
            headers[Exchange.HTTP_RESPONSE_CODE] = HTTP_INTERNAL_ERROR // Internal Server Error
            headers[Exchange.CONTENT_TYPE] = "application/json"
            val sw = StringWriter()
            th.printStackTrace(PrintWriter(sw))
            val traceLines = "$sw".lines().map { it.trim() }.find { it.isNotEmpty() }
            exchange.message.body = mapOf(
                "msg" to th.message,
                "trace" to traceLines,
            ).encodeJson()
            log.error(th) { th.message }
        }
    }

}