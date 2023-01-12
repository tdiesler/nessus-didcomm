package org.nessus.didcomm.protocol

import mu.KotlinLogging

abstract class Protocol {
    val log = KotlinLogging.logger {}
    abstract val protocolUri: String

    protected fun checkProtocol(mex: MessageExchange) {
        check(mex.last.protocolUri == protocolUri) { "Invalid protocol: ${mex.last.protocolUri}" }

    }
}