package org.nessus.didcomm.service

import id.walt.servicematrix.ServiceProvider
import org.apache.camel.CamelContext
import org.apache.camel.builder.RouteBuilder
import org.apache.camel.impl.DefaultCamelContext
import org.nessus.didcomm.protocol.EndpointMessage
import org.nessus.didcomm.protocol.MessageListener
import java.net.URL


class CamelEndpointService: EndpointService<CamelContext>() {

    companion object: ServiceProvider {
        private val implementation = CamelEndpointService()
        override fun getService() = implementation
    }

    override val endpointUrl: String?
        get() = "http://host.docker.internal:9030"

    override fun startEndpoint(listener: MessageListener?): CamelContext {
        val port = URL(endpointUrl).port
        log.info("Starting Camel endpoint on: $port")
        val camelctx: CamelContext = DefaultCamelContext()
        val dispatcher = listener ?: MessageDispatchService.getService()
        camelctx.addRoutes(object: RouteBuilder(camelctx) {
            override fun configure() {
                from("undertow:http://0.0.0.0:${port}?matchOnUriPrefix=true")
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