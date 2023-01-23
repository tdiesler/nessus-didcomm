package org.nessus.didcomm.protocol

import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.service.DataModelService
import org.nessus.didcomm.service.DidDocumentService
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.service.MessageDispatchService
import org.nessus.didcomm.service.ProtocolKey
import org.nessus.didcomm.service.ProtocolService
import org.nessus.didcomm.service.ProtocolWrapperKey
import org.nessus.didcomm.util.toUnionMap
import org.nessus.didcomm.wallet.Wallet

abstract class Protocol {
    val log = KotlinLogging.logger {}

    abstract val protocolUri: String

    val didService get() = DidService.getService()
    val diddocService get() = DidDocumentService.getService()
    val modelService get() = DataModelService.getService()
    val protocolService get() = ProtocolService.getService()

    fun <P: Protocol> getProtocol(key: ProtocolKey<P>): P {
        return protocolService.getProtocol(key)
    }
}

abstract class ProtocolWrapper<W: ProtocolWrapper<W, P>, P: Protocol>(
    protected val protocol: P,
    protected val mex: MessageExchange
) {
    val log = KotlinLogging.logger {}

    val dispatchService get() = MessageDispatchService.getService()
    val modelService get() = DataModelService.getService()

    open fun invokeMethod(to: Wallet, messageType: String): Boolean {
        throw IllegalStateException("Dispatch not supported in protocol wrapper: ${protocol.protocolUri}")
    }

    fun <T :ProtocolWrapper<T, *>> withProtocol(key: ProtocolWrapperKey<T>): T {
        return mex.withProtocol(key)
    }

    fun getMessageExchange(): MessageExchange {
        return mex
    }

    @Suppress("UNCHECKED_CAST")
    fun dispatchTo(target: Wallet, headers: Map<String, Any?> = mapOf()): W {

        // Merge headers and create the follow-up message if needed
        val effectiveHeaders = mex.last.headers.toUnionMap(headers).toMutableMap() as MutableMap<String, Any?>
        if (effectiveHeaders != mex.last.headers) {
            mex.addMessage(EndpointMessage(mex.last.body, effectiveHeaders.toMap()))
        }

        dispatchService.dispatchToWallet(target, mex)
        return this as W
    }

    fun dispatchToDid(did: Did): W {
        TODO("dispatchToDid")
    }

    @Suppress("UNCHECKED_CAST")
    fun dispatchToEndpoint(url: String, epm: EndpointMessage): W {
        dispatchService.dispatchToEndpoint(url, epm)
        return this as W
    }
}
