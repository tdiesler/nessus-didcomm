package org.nessus.didcomm.service

import id.walt.servicematrix.ServiceProvider
import mu.KotlinLogging
import org.apache.camel.CamelContext
import org.apache.camel.builder.RouteBuilder
import org.apache.camel.impl.DefaultCamelContext
import org.nessus.didcomm.protocol.EndpointMessage
import org.nessus.didcomm.protocol.MessageListener
import org.nessus.didcomm.wallet.Wallet


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