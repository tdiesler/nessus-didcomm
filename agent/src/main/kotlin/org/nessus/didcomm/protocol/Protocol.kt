package org.nessus.didcomm.protocol

import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocol.Companion.PROTOCOL_METHOD_RECEIVE_INVITATION
import org.nessus.didcomm.service.MessageDispatchService
import org.nessus.didcomm.service.ProtocolWrapperKey
import org.nessus.didcomm.util.toUnionMap
import org.nessus.didcomm.wallet.Wallet

abstract class Protocol {
    val log = KotlinLogging.logger {}

    abstract val protocolUri: String

    open fun invokeMethod(to: Wallet, method: String, mex: MessageExchange): Boolean {
        throw IllegalStateException("Dispatch not supported in protocol: $protocolUri")
    }
}

abstract class ProtocolWrapper<W: ProtocolWrapper<W, P>, P: Protocol>(
    protected val protocol: P,
    protected val mex: MessageExchange
) {
    val log = KotlinLogging.logger {}

    open fun invokeMethod(to: Wallet, method: String): Boolean {
        return protocol.invokeMethod(to, method, mex)
    }

    fun withProtocol(key: ProtocolWrapperKey<W>): W {
        return mex.withProtocol(key)
    }

    fun peekMessageExchange(): MessageExchange {
        return mex
    }

    @Suppress("UNCHECKED_CAST")
    fun dispatchTo(target: Wallet, headers: Map<String, Any?> = mapOf()): W {

        // Merge headers and create the follow-up message if needed
        val effectiveHeaders = mex.last.headers.toUnionMap(headers).toMutableMap() as MutableMap<String, Any?>
        if (effectiveHeaders != mex.last.headers) {
            mex.addMessage(EndpointMessage(mex.last.body, effectiveHeaders.toMap()))
        }

        val protocolMethod = mex.last.protocolMethod as? String
        if (protocolMethod == PROTOCOL_METHOD_RECEIVE_INVITATION) {
            val thid = mex.last.threadId ?: throw IllegalStateException("No threadId in ${mex.last}")
            mex.addThreadIdFuture(thid)
        }

        MessageDispatchService.getService().dispatchToWallet(target, mex)
        return this as W
    }

    fun dispatchToDid(did: Did, headers: Map<String, Any?> = mapOf()): W {
        TODO("dispatchToDid")
    }

    fun dispatchToEndpoint(uri: String, headers: Map<String, Any?> = mapOf()): W {
        TODO("dispatchToEndpoint")
    }
}
