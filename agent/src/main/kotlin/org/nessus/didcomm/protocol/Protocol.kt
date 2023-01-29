package org.nessus.didcomm.protocol

import id.walt.services.keystore.KeyStoreService
import mu.KLogger
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.service.*
import org.nessus.didcomm.util.toUnionMap
import org.nessus.didcomm.wallet.Wallet
import java.time.OffsetDateTime
import java.time.ZoneOffset

abstract class Protocol<T: Protocol<T>>(protected val mex: MessageExchange) {

    abstract val log: KLogger
    abstract val protocolUri: String

    val didService get() = DidService.getService()
    val diddocService get() = DidDocumentService.getService()
    val dispatchService get() = MessageDispatchService.getService()
    val keyStore get() = KeyStoreService.getService()
    val modelService get() = DataModelService.getService()
    val protocolService get() = ProtocolService.getService()

    val nowIso8601: OffsetDateTime get() = OffsetDateTime.now(ZoneOffset.UTC)

    internal open fun invokeMethod(to: Wallet, messageType: String): Boolean {
        throw IllegalStateException("Dispatch not supported in protocol wrapper: $protocolUri")
    }

    fun <T :Protocol<T>> withProtocol(key: ProtocolKey<T>): T {
        return mex.withProtocol(key)
    }

    fun getMessageExchange(): MessageExchange {
        return mex
    }

    @Suppress("UNCHECKED_CAST")
    fun dispatchTo(target: Wallet, headers: Map<String, Any?> = mapOf()): T {

        // Merge headers and create the follow-up message if needed
        val effectiveHeaders = mex.last.headers.toUnionMap(headers).toMutableMap() as MutableMap<String, Any?>
        if (effectiveHeaders != mex.last.headers) {
            mex.addMessage(EndpointMessage(mex.last.body, effectiveHeaders.toMap()))
        }

        dispatchService.dispatchToWallet(target, mex)
        return this as T
    }

    fun dispatchToDid(did: Did): T {
        TODO("dispatchToDid")
    }

    @Suppress("UNCHECKED_CAST")
    fun dispatchToEndpoint(url: String?, epm: EndpointMessage): T {
        requireNotNull(url) { "No endpoint url" }
        dispatchService.dispatchToEndpoint(url, epm)
        return this as T
    }
}
