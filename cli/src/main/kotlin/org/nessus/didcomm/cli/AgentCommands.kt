/*-
 * #%L
 * Nessus DIDComm :: CLI
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
package org.nessus.didcomm.cli

import org.apache.camel.CamelContext
import org.nessus.didcomm.util.AttachmentKey
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.ScopeType.INHERIT

@Command(
    name = "agent",
    description = ["Agent related commands"],
)
class AgentCommands: AbstractBaseCommand() {

    @Option(names = ["--wallet" ], scope = INHERIT, description = ["An Wallet alias"])
    var walletAlias: String? = null

    @Option(names = ["--uri" ], scope = INHERIT, description = ["The URI of the form [type:][host:]port"])
    var uri: String? = null

    @Command(name = "start", description = ["Start the agent's endpoint"])
    fun start(): Int {
        val eps = getEndpointSpec(uri)
        check(eps.type.lowercase() == "camel") { "Unsupported endpoint type: $eps" }
        val context = endpointService.startEndpoint("http://${eps.host}:${eps.port}") as CamelContext
        echo("Started ${eps.type} endpoint on ${eps.host}:${eps.port}")
        val key = AttachmentKey("$eps", CamelContext::class)
        cliService.putAttachment(key, context)
        return 0
    }

    @Command(name = "stop", description = ["Stop the agent's endpoint"])
    fun stop(): Int {
        val eps = getEndpointSpec(uri)
        val key = AttachmentKey("$eps", CamelContext::class)
        val context = cliService.removeAttachment(key)
        checkNotNull(context) { "No endpoint context" }
        context.stop()
        echo("Stopped ${eps.type} endpoint on ${eps.host}:${eps.port}")
        return 0
    }

    private fun getEndpointSpec(uri: String?): EndpointSpec {
        if (uri != null)
            return EndpointSpec.valueOf(uri)
        val agentHost = System.getenv("NESSUS_AGENT_HOST") ?: "localhost"
        val userPort = System.getenv("NESSUS_USER_PORT") ?: "9000"
        return EndpointSpec.valueOf("${agentHost}:${userPort}")
    }
}

data class EndpointSpec(
    val type: String,
    val host: String,
    val port: Int,
) {
    companion object {
        private const val DEFAULT_ENDPOINT_TYPE = "Camel"

        fun valueOf(uri: String): EndpointSpec {
            val toks = uri.split(':')
            fun checkType(type: String): String {
                check(type == DEFAULT_ENDPOINT_TYPE) { "Unsupported endpoint type: $type" }
                return type
            }
            fun checkHost(host: String): String {
                check( !host.startsWith("//")) { "Unsupported host: $host" }
                return host
            }
            return when (toks.size) {
                3 -> EndpointSpec(checkType(toks[0]), checkHost(toks[1]), toks[2].toInt())
                2 -> EndpointSpec(DEFAULT_ENDPOINT_TYPE, checkHost(toks[0]), toks[1].toInt())
                1 -> EndpointSpec(DEFAULT_ENDPOINT_TYPE,"localhost", toks[0].toInt())
                else -> throw IllegalArgumentException("Invalid URI spec: $uri")
            }
        }
    }

    override fun toString() = "$type:$host:$port"
}
