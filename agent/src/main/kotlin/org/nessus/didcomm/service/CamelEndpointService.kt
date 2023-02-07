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

import id.walt.servicematrix.ServiceProvider
import mu.KotlinLogging
import org.apache.camel.CamelContext
import org.apache.camel.builder.RouteBuilder
import org.apache.camel.impl.DefaultCamelContext
import org.nessus.didcomm.protocol.EndpointMessage
import org.nessus.didcomm.protocol.MessageListener


class CamelEndpointService: EndpointService<CamelContext>() {

    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = CamelEndpointService()
        override fun getService() = implementation
    }

    override fun startEndpoint(endpointUrl: String, listener: MessageListener?): CamelContext {
        log.info("Starting Camel endpoint on: $endpointUrl")
        val camelctx: CamelContext = DefaultCamelContext()
        val dispatcher = listener ?: MessageDispatchService.getService()
        camelctx.addRoutes(object: RouteBuilder(camelctx) {
            override fun configure() {
                from("undertow:$endpointUrl?matchOnUriPrefix=true")
                    .log("Req: \${headers.CamelHttpMethod} \${headers.CamelHttpPath} \${body}")
                    .process {
                        val headers = it.message.headers
                        val body = it.message.getBody(String::class.java)
                        dispatcher.invoke(EndpointMessage(body, headers))
                    }
            }
        })
        camelctx.start()
        return camelctx
    }
}
