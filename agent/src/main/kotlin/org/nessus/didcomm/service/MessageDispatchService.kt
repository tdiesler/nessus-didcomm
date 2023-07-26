/*-
 * #%L
 * Nessus DIDComm :: Core
 * %%
 * Copyright (C) 2022 Nessus
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package org.nessus.didcomm.service

import id.walt.common.prettyPrint
import org.didcommx.didcomm.common.Typ
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.PackPlaintextParams
import org.didcommx.didcomm.model.PackSignedParams
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.EndpointMessage
import org.nessus.didcomm.model.EndpointMessage.Companion.MESSAGE_HEADER_ENDPOINT_URL
import org.nessus.didcomm.model.EndpointMessage.Companion.MESSAGE_HEADER_ID
import org.nessus.didcomm.model.EndpointMessage.Companion.MESSAGE_HEADER_THID
import org.nessus.didcomm.model.EndpointMessage.Companion.MESSAGE_HEADER_TYPE
import org.nessus.didcomm.protocol.ForwardMessageV2
import org.nessus.didcomm.protocol.RoutingProtocolV2.Companion.ROUTING_MESSAGE_TYPE_FORWARD_V2
import org.nessus.didcomm.util.NessusRuntimeException
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import java.util.UUID

/**
 * The MessageDispatchService handles all outgoing messages
 */
object MessageDispatchService: ObjectService<MessageDispatchService>() {

    override fun getService() = apply { }

    private val didComm get() = DidCommService.getService()
    private val didService get() = DidService.getService()
    private val httpService get() = HttpService.getService()

    fun dispatchPlainMessage(pcon: Connection, origMsg: Message, fromPrior: String? = null, consumer: (EndpointMessage) -> Unit) {

        val builder = PackPlaintextParams.builder(origMsg)
        fromPrior?.also { builder.fromPriorIssuerKid(it) }

        val packResult = didComm.packPlaintext(builder.build())

        val ctx = DispatchContext(pcon, origMsg, packResult.packedMessage)
        consumer(ctx.packedEpm)

        dispatchToRemoteEndpoint(ctx)
    }

    fun dispatchSignedMessage(pcon: Connection, origMsg: Message, fromPrior: String? = null, consumer: (EndpointMessage) -> Unit) {

        val builder = PackSignedParams.builder(origMsg, pcon.myDid.uri)
        fromPrior?.also { builder.fromPriorIssuerKid(it) }

        val packResult = didComm.packSigned(builder.build())

        val ctx = DispatchContext(pcon, origMsg, packResult.packedMessage)
        consumer(ctx.packedEpm)

        dispatchToRemoteEndpoint(ctx)
    }

    fun dispatchEncryptedMessage(pcon: Connection, origMsg: Message, fromPrior: String? = null, consumer: (EndpointMessage) -> Unit) {

        val builder = PackEncryptedParams.builder(origMsg, pcon.theirDid.uri)
            .signFrom(pcon.myDid.uri)
            .from(pcon.myDid.uri)
            .forward(false)
        fromPrior?.also { builder.fromPriorIssuerKid(it) }

        val packResult = didComm.packEncrypted(builder.build())
        val ctx = DispatchContext(pcon, origMsg, packResult.packedMessage)

        consumer(ctx.packedEpm)

        dispatchToRemoteEndpoint(ctx)
    }

    fun dispatchToRemoteEndpoint(endpointUrl: String, epm: EndpointMessage): Boolean {
        val httpClient = httpService.httpClient()
        val res = httpClient.post(endpointUrl, epm.body, headers = epm.headers.mapValues { (_, v) -> v.toString() })
        if (!res.isSuccessful) {
            val error = res.body?.string()
            log.error { error?.prettyPrint() }
            when {
                !error.isNullOrEmpty() -> throw NessusRuntimeException(error)
                else -> throw IllegalStateException("Call failed with ${res.code} ${res.message}")
            }
        }
        return true
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun dispatchToRemoteEndpoint(ctx: DispatchContext): Boolean {
        val epm = ctx.effectiveEpm
        val effectiveEndpointUrl = ctx.effectiveEndpointUrl
        if (effectiveEndpointUrl != ctx.pcon.theirEndpointUrl) {
            log.info { "Routing redirect: ${ctx.pcon.theirEndpointUrl} => $effectiveEndpointUrl" }
        }
        return dispatchToRemoteEndpoint(effectiveEndpointUrl, epm)
    }

    private class DispatchContext(val pcon: Connection, val origMsg: Message, val packedMsg: String) {

        val packedJson = packedMsg.decodeJson()
        val typ = when {
            packedJson["ciphertext"] != null -> Typ.Encrypted.typ
            packedJson["signatures"] != null -> Typ.Signed.typ
            packedJson["typ"] != null -> Typ.Plaintext.typ
            else -> "unsupported-message-typ"
         }

        val recipientDidDoc = checkNotNull(didService.loadOrResolveDidDoc(pcon.theirDid.uri)) {
            "Cannot resolve recipient DidDoc: ${pcon.shortString()}"
        }

        val recipientDidCommService get() = checkNotNull(recipientDidDoc.didCommServices.firstOrNull()) {
            "No recipient DIDComm Service"
        }

        val recipientEndpointUrl = recipientDidCommService.serviceEndpoint

        val packedEpm = EndpointMessage.Builder(packedMsg, mapOf(
                MESSAGE_HEADER_ENDPOINT_URL to recipientEndpointUrl,
                MESSAGE_HEADER_ID to "${origMsg.id}.packed",
                MESSAGE_HEADER_THID to origMsg.thid,
                MESSAGE_HEADER_TYPE to typ))
            .outbound().build()

        val routingKey get() = getEffectiveRoutingKey()

        val mediatorDidDoc get() = routingKey?.let { rk ->
            checkNotNull(didService.loadOrResolveDidDoc(routingKey!!)) { "Cannot resolve routing DidDoc for: $rk" }
        }

        val mediatorDidCommService get() = mediatorDidDoc?.let {
            checkNotNull(it.didCommServices.firstOrNull()) { "No mediator DIDComm Service" }
        }

        val effectiveDidCommService get() = mediatorDidCommService ?: recipientDidCommService
        val effectiveEndpointUrl get () = effectiveDidCommService.serviceEndpoint

        val effectiveEpm get() = run {
            val routingKey = getEffectiveRoutingKey()
            if (routingKey != null) {
                log.info { "Effective routing key: $routingKey" }
                val jsonData = Attachment.Data.Json.parse(mapOf("json" to packedMsg.decodeJson()))
                val attachment = Attachment.Builder("${UUID.randomUUID()}", jsonData).build()
                val forwardMsg = ForwardMessageV2.Builder("${UUID.randomUUID()}", ROUTING_MESSAGE_TYPE_FORWARD_V2)
                    .to(listOf(routingKey))
                    .next(pcon.theirDid.uri)
                    .attachments(listOf(attachment))
                    .build().toMessage()
                log.info { "Forward message: ${forwardMsg.encodeJson(true)}" }
                val packParams = PackEncryptedParams.builder(forwardMsg, routingKey)
                    .signFrom(pcon.myDid.uri)
                    .from(pcon.myDid.uri)
                    .build()
                val packResult = didComm.packEncrypted(packParams)
                val packedForwardMsg = packResult.packedMessage
                EndpointMessage.Builder(packedForwardMsg, mapOf(
                        MESSAGE_HEADER_ENDPOINT_URL to effectiveEndpointUrl,
                        MESSAGE_HEADER_ID to "${forwardMsg.id}.packed",
                        MESSAGE_HEADER_THID to origMsg.thid,
                        MESSAGE_HEADER_TYPE to Typ.Encrypted.typ))
                    .outbound().build()
            } else {
                packedEpm
            }
        }

        private fun getEffectiveRoutingKey(): String? {
            val isDid = { x:String -> x.startsWith("did:") }
            val firstRoutingKey = recipientDidCommService.routingKeys.firstOrNull()
            if (firstRoutingKey != null) {
                check(isDid(firstRoutingKey)) { "Unexpected routing key: $firstRoutingKey" }
                return firstRoutingKey
            }
            val endpointUrl = recipientDidCommService.serviceEndpoint
            if (isDid(endpointUrl)) {
                return endpointUrl
            }
            return null
        }
    }

}
