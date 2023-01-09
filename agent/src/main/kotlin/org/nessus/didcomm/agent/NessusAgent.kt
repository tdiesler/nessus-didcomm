/*-
 * #%L
 * Nessus DIDComm :: Services :: Agent
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
package org.nessus.didcomm.agent

import mu.KotlinLogging
import org.apache.camel.CamelContext
import org.apache.camel.Processor
import org.apache.camel.builder.RouteBuilder
import org.apache.camel.impl.DefaultCamelContext


class NessusAgent {

    private val log = KotlinLogging.logger {}

    companion object {
        private val implementation = NessusAgent()
        fun getService() = implementation
    }

    fun startEndpoint(requestProcessor: Processor, agentPort : Int = 9030): CamelContext {
        log.info("Starting Nessus endpoint on: $agentPort")
        val camelctx: CamelContext = DefaultCamelContext()
        camelctx.addRoutes(object: RouteBuilder(camelctx) {
            override fun configure() {
                from("undertow:http://0.0.0.0:${agentPort}?matchOnUriPrefix=true")
                    .log("Req: \${headers.CamelHttpMethod} \${headers.CamelHttpPath} \${body}")
                    .process(requestProcessor)
            }
        })
        camelctx.start()
        return camelctx
    }
}
