package org.nessus.didcomm.protocol

import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.protocol.RFC0434OutOfBandProtocol.Companion.PROTOCOL_METHOD_RECEIVE_INVITATION
import org.nessus.didcomm.service.MessageDispatchService
import org.nessus.didcomm.service.ProtocolKey
import org.nessus.didcomm.util.toUnionMap
import org.nessus.didcomm.wallet.Wallet

abstract class Protocol<T: Protocol<T>>(protected val messageExchange: MessageExchange) {
    val log = KotlinLogging.logger {}

    abstract val protocolUri: String

    open fun invokeMethod(to: Wallet, method: String): Boolean {
        throw IllegalStateException("Dispatch not supported in protocol: $protocolUri")
    }

    fun <T: Protocol<T>> withProtocol(key: ProtocolKey<T>): T {
        return messageExchange.withProtocol(key)
    }

    fun peekMessageExchange(): MessageExchange {
        return messageExchange
    }

    @Suppress("UNCHECKED_CAST")
    fun dispatchToWallet(target: Wallet, headers: Map<String, Any?> = mapOf()): T {

        // Merge headers and create the follow-up message if needed
        val effectiveHeaders = messageExchange.last.headers.toUnionMap(headers).toMutableMap() as MutableMap<String, Any?>
        if (effectiveHeaders != messageExchange.last.headers) {
            messageExchange.addMessage(EndpointMessage(messageExchange.last.body, effectiveHeaders.toMap()))
        }

        val mex = messageExchange
        val protocolMethod = mex.last.protocolMethod as? String
        if (protocolMethod == PROTOCOL_METHOD_RECEIVE_INVITATION) {
            val thid = mex.last.threadId ?: throw IllegalStateException("No threadId in ${mex.last}")
            messageExchange.addThreadIdFuture(thid)
        }

        MessageDispatchService.getService().dispatchToWallet(target, messageExchange)
        return this as T
    }

    fun dispatchToDid(did: Did, headers: Map<String, Any?> = mapOf()): T {
        TODO("dispatchToDid")
    }

    fun dispatchToEndpoint(uri: String, headers: Map<String, Any?> = mapOf()): T {
        TODO("dispatchToEndpoint")
    }

}