package org.nessus.didcomm.protocol

import mu.KotlinLogging
import org.nessus.didcomm.wallet.Wallet

abstract class Protocol {
    val log = KotlinLogging.logger {}
    abstract val protocolUri: String

    protected fun checkProtocol(mex: MessageExchange) {
        check(mex.last.protocolUri == protocolUri) { "Invalid protocol: ${mex.last.protocolUri}" }
    }

    open fun sendTo(to: Wallet, mex: MessageExchange): Boolean {
        throw IllegalStateException("Dispatch not supported in protocol: $protocolUri")
    }
}