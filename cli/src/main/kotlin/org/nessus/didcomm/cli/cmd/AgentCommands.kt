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
package org.nessus.didcomm.cli.cmd

import org.apache.camel.CamelContext
import org.nessus.didcomm.cli.cmd.AgentCommands.EndpointSpec.Companion.valueOf
import org.nessus.didcomm.util.AttachmentKey
import picocli.CommandLine.Command
import picocli.CommandLine.Parameters
import picocli.CommandLine.ScopeType.INHERIT

@Command(
    name = "agent",
    description = ["Agent related commands"],
)
class AgentCommands: AbstractBaseCommand() {

    @Parameters(paramLabel = "URI", scope = INHERIT, description = ["The URI of the form [type:][host:]port"])
    var uri: String? = null

    data class EndpointSpec(
        val type: String,
        val host: String,
        val port: Int,
    ) {
        companion object {
            fun valueOf(uri: String): EndpointSpec {
                val toks = uri.split(':')
                return when (toks.size) {
                    3 -> EndpointSpec(toks[0], toks[1], toks[2].toInt())
                    2 -> EndpointSpec("Camel", toks[0], toks[1].toInt())
                    1 -> EndpointSpec("Camel", "0.0.0.0", toks[0].toInt())
                    else -> throw IllegalArgumentException("Invalid URI spec: $uri")
                }
            }
        }
        override fun toString() = "$type:$host:$port"
    }

    @Command(name = "start")
    fun start(): Int {
        val eps = valueOf(uri!!)
        check(eps.type.lowercase() == "camel") { "Unsupported endpoint type: $eps" }
        val context = endpointService.startEndpoint("http://${eps.host}:${eps.port}")
        println("Started ${eps.type} endpoint on ${eps.host}:${eps.port}")
        val key = AttachmentKey("$eps", CamelContext::class.java)
        cliService.putAttachment(key, context)
        return 0
    }

    @Command(name = "stop")
    fun stop(): Int {
        val eps = valueOf(uri!!)
        val key = AttachmentKey("$eps", CamelContext::class.java)
        val context = cliService.removeAttachment(key)
        checkNotNull(context) { "No endpoint context" }
        context.stop()
        println("Stopped ${eps.type} endpoint on ${eps.host}:${eps.port}")
        return 0
    }
}

