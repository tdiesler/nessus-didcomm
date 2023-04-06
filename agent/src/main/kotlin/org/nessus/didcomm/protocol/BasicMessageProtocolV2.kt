/*-
 * #%L
 * Nessus DIDComm :: Agent
 * %%
 * Copyright (C) 2022 - 2023 Nessus
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
package org.nessus.didcomm.protocol

import id.walt.common.prettyPrint
import mu.KotlinLogging
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.message.MessageBuilder
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.EndpointMessage
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.MessageExchange.Companion.CONNECTION_ATTACHMENT_KEY
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.BASIC_MESSAGE_PROTOCOL_V2
import org.nessus.didcomm.util.dateTimeInstant
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.encodeJson
import java.time.OffsetDateTime
import java.util.UUID

/**
 * Nessus DIDComm: Basic Message Protocol 2.0
 * https://github.com/tdiesler/nessus-didcomm/tree/main/features/0095-basic-message
 */
class BasicMessageProtocolV2(mex: MessageExchange): Protocol<BasicMessageProtocolV2>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = BASIC_MESSAGE_PROTOCOL_V2.uri

    companion object {
        val BASIC_MESSAGE_TYPE_V2 = "${BASIC_MESSAGE_PROTOCOL_V2.uri}/message"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.NESSUS)

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            BASIC_MESSAGE_TYPE_V2 -> receiveMessage()
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

    fun sendPlaintextMessage(message: String, connection: Connection? = null): BasicMessageProtocolV2 {

        val pcon = connection ?: mex.getAttachment(CONNECTION_ATTACHMENT_KEY)
        checkNotNull(pcon) { "No connection" }

        check(pcon.state == ConnectionState.ACTIVE) { "Connection not active: $pcon" }

        val sender = modelService.findWalletByVerkey(pcon.myDid.verkey)
        checkNotNull(sender) { "No sender wallet" }

        // Use my previous MessageExchange
        val senderMex = MessageExchange.findByConnectionId(pcon.id)
        checkNotNull(senderMex) { "No message exchange for: ${pcon.shortString()}" }

        val protocol = senderMex.withProtocol(BASIC_MESSAGE_PROTOCOL_V2)

        val senderDid = pcon.myDid
        val recipientDid = pcon.theirDid

        val basicMessage = BasicMessageV2.Builder(
                id = "${UUID.randomUUID()}",
                type = BASIC_MESSAGE_TYPE_V2)
            .from(senderDid.uri)
            .to(listOf(recipientDid.uri))
            .createdTime(dateTimeNow())
            .content(message)
            .build()

        val basicMsg = basicMessage.toMessage()
        senderMex.addMessage(EndpointMessage.Builder(basicMsg).outbound().build()).last
        log.info { "Sender (${sender.name}) creates Basic Message: ${basicMsg.encodeJson(true)}" }

        dispatchPlainMessage(pcon, basicMsg) { packedEpm ->
            log.info { "Sender (${sender.name}) sends Basic Message: ${packedEpm.prettyPrint()}" }
        }
        return protocol
    }

    fun sendSignedMessage(message: String, connection: Connection? = null): BasicMessageProtocolV2 {

        val pcon = connection ?: mex.getAttachment(CONNECTION_ATTACHMENT_KEY)
        checkNotNull(pcon) { "No connection" }

        check(pcon.state == ConnectionState.ACTIVE) { "Connection not active: $pcon" }

        val sender = modelService.findWalletByVerkey(pcon.myDid.verkey)
        checkNotNull(sender) { "No sender wallet" }

        // Use my previous MessageExchange
        val senderMex = MessageExchange.findByConnectionId(pcon.id)
        checkNotNull(senderMex) { "No message exchange for: ${pcon.shortString()}" }

        val protocol = senderMex.withProtocol(BASIC_MESSAGE_PROTOCOL_V2)

        val senderDid = pcon.myDid
        val recipientDid = pcon.theirDid

        val basicMessage = BasicMessageV2.Builder(
                id = "${UUID.randomUUID()}",
                type = BASIC_MESSAGE_TYPE_V2)
            .from(senderDid.uri)
            .to(listOf(recipientDid.uri))
            .createdTime(dateTimeNow())
            .content(message)
            .build()

        val basicMsg = basicMessage.toMessage()
        senderMex.addMessage(EndpointMessage.Builder(basicMsg).outbound().build()).last
        log.info { "Sender (${sender.name}) creates Basic Message: ${basicMsg.encodeJson(true)}" }

        dispatchSignedMessage(pcon, basicMsg) { packedEpm ->
            log.info { "Sender (${sender.name}) sends Basic Message: ${packedEpm.prettyPrint()}" }
        }
        return protocol
    }

    fun sendEncryptedMessage(message: String, connection: Connection? = null): BasicMessageProtocolV2 {

        val pcon = connection ?: mex.getAttachment(CONNECTION_ATTACHMENT_KEY)
        checkNotNull(pcon) { "No connection" }

        check(pcon.state == ConnectionState.ACTIVE) { "Connection not active: $pcon" }

        val sender = modelService.findWalletByVerkey(pcon.myDid.verkey)
        checkNotNull(sender) { "No sender wallet" }

        // Use my previous MessageExchange
        val senderMex = MessageExchange.findByConnectionId(pcon.id)
        checkNotNull(senderMex) { "No message exchange for: ${pcon.shortString()}" }

        val protocol = senderMex.withProtocol(BASIC_MESSAGE_PROTOCOL_V2)

        val senderDid = pcon.myDid
        val recipientDid = pcon.theirDid

        val basicMessage = BasicMessageV2.Builder(
                id = "${UUID.randomUUID()}",
                type = BASIC_MESSAGE_TYPE_V2)
            .from(senderDid.uri)
            .to(listOf(recipientDid.uri))
            .createdTime(dateTimeNow())
            .content(message)
            .build()

        val basicMsg = basicMessage.toMessage()
        senderMex.addMessage(EndpointMessage.Builder(basicMsg).outbound().build())
        log.info { "Sender (${sender.name}) created Basic Message: ${basicMsg.encodeJson(true)}" }

        dispatchEncryptedMessage(pcon, basicMsg) { packedEpm ->
            log.info { "Sender (${sender.name}) sends Basic Message: ${packedEpm.prettyPrint()}" }
        }
        return protocol
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun receiveMessage(): BasicMessageProtocolV2 {

        val basicMessageMsg = mex.last.body as Message
        mex.checkLastMessageType(BASIC_MESSAGE_TYPE_V2)

        BasicMessageV2.fromMessage(basicMessageMsg)
        log.info { "Received basic message: ${basicMessageMsg.encodeJson(true)}" }

        return this
    }
}

class BasicMessageV2(
    val id: String,
    val type: String,
    val thid: String?,
    val from: String?,
    val to: List<String>?,
    val createdTime: OffsetDateTime?,
    val content: String?,
) {
    internal constructor(builder: Builder): this(
        id = builder.id,
        type = builder.type,
        thid = builder.thid,
        from = builder.from,
        to = builder.to,
        createdTime = builder.createdTime,
        content = builder.content,
    )

    companion object {
        fun fromMessage(msg: Message): BasicMessageV2 {
            requireNotNull(msg.from) { "No from" }
            val createdTime = msg.createdTime?.run { dateTimeInstant(msg.createdTime!!) }
            val content = msg.body["content"] as? String
            return Builder(msg.id, msg.type)
                .thid(msg.thid)
                .from(msg.from)
                .to(msg.to)
                .createdTime(createdTime)
                .content(content)
                .build()
        }
    }

    fun toMessage(): Message {
        val body = LinkedHashMap<String, Any>()
        content?.also { body["content"] = content }
        return MessageBuilder(id, body, type)
            .thid(thid)
            .from(from)
            .to(to)
            .createdTime(createdTime?.toInstant()?.epochSecond)
            .build()
    }

    class Builder(
        val id: String,
        val type: String) {

        internal var thid: String? = null
            private set

        internal var from: String? = null
            private set

        internal var to: List<String>? = null
            private set

        internal var createdTime: OffsetDateTime? = null
            private set

        internal var content: String? = null
            private set

        fun thid(thid: String?) = apply { this.thid = thid }
        fun from(from: String?) = apply { this.from = from }
        fun to(to: List<String>?) = apply { this.to = to }
        fun createdTime(createdTime: OffsetDateTime?) = apply { this.createdTime = createdTime }
        fun content(comment: String?) = apply { this.content = comment }

        fun build(): BasicMessageV2 {
            return BasicMessageV2(this)
        }
    }
}
