package org.nessus.didcomm.protocol

import mu.KotlinLogging

abstract class ProtocolHandler {

    val log = KotlinLogging.logger {}
}

data class Response(
    val message: String?,
    val error: String? = null
)