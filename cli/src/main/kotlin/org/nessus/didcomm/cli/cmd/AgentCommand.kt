package org.nessus.didcomm.cli.cmd

import org.apache.camel.CamelContext
import org.nessus.didcomm.util.AttachmentKey
import picocli.CommandLine.Command
import picocli.CommandLine.Parameters
import picocli.CommandLine.ScopeType.INHERIT

@Command(
    name = "agent",
    description = ["Agent related commands"],
)
class AgentCommand: AbstractBaseCommand() {

    @Parameters(paramLabel = "URI", scope = INHERIT, description = ["The URI of the form [type:][host:]port"])
    var uri: String? = null

    data class EndpointSpec(
        val type: String,
        val host: String,
        val port: Int,
    ) {
        override fun toString() = "$type:$host:$port"
    }

    @Command(name = "start")
    fun start(): Int {
        val eps = endpointSpecFromUri(uri!!)
        check(eps.type == "camel") { "Unsupported endpoint type: $eps" }
        val context = endpointService.startEndpoint("http://${eps.host}:${eps.port}")
        println("Started ${eps.type} endpoint on ${eps.host}:${eps.port}")
        val key = AttachmentKey("$eps", CamelContext::class.java)
        cliService.putAttachment(key, context)
        return 0
    }

    @Command(name = "stop")
    fun stop(): Int {
        val eps = endpointSpecFromUri(uri!!)
        val key = AttachmentKey("$eps", CamelContext::class.java)
        val context = cliService.removeAttachment(key)
        checkNotNull(context) { "No endpoint context" }
        context.stop()
        println("Stopped ${eps.type} endpoint on ${eps.host}:${eps.port}")
        return 0
    }

    private fun endpointSpecFromUri(uri: String): EndpointSpec {
        val toks = uri.split(':')
        return when (toks.size) {
            3 -> EndpointSpec(toks[0], toks[1], toks[2].toInt())
            2 -> EndpointSpec("camel", toks[0], toks[1].toInt())
            1 -> EndpointSpec("camel", "0.0.0.0", toks[0].toInt())
            else -> throw IllegalArgumentException("Invalid URI spec: $uri")
        }
    }
}

