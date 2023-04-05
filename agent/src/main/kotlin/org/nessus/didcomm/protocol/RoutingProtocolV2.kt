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

import mu.KotlinLogging
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.message.MessageBuilder
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.ROUTING_PROTOCOL_V2

/**
 * Routing Protocol 2.0
 * https://identity.foundation/didcomm-messaging/spec/#routing-protocol-20
 */
class RoutingProtocolV2(mex: MessageExchange): Protocol<RoutingProtocolV2>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = ROUTING_PROTOCOL_V2.uri

    companion object {
        val ROUTING_MESSAGE_TYPE_FORWARD_V2 = "${ROUTING_PROTOCOL_V2.uri}/forward"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.NESSUS)

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            ROUTING_MESSAGE_TYPE_FORWARD_V2 -> receiveForwardMessage(to)
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

    private fun receiveForwardMessage(to: Wallet) {
        val forwardMsg = mex.last.body as Message
        mex.checkLastMessageType(ROUTING_MESSAGE_TYPE_FORWARD_V2)

        val forwardV2 = ForwardMessageV2.fromMessage(forwardMsg)
        val nextDidDoc = didService.resolveDidDoc(forwardV2.next)
        checkNotNull(nextDidDoc) { "Cannot resolve next DidDoc for: ${forwardV2.next}" }
    }
}

/**
 * Forward message
 *
 * {
 *     "type": "https://didcomm.org/routing/2.0/forward",
 *     "id": "abc123xyz456",
 *     "to": ["did:example:mediator"],
 *     "expires_time": 1516385931,
 *     "body":{
 *         "next": "did:foo:1234abcd"
 *     },
 *     "attachments": [
 *         // The payload(s) to be forwarded
 *     ]
 * }
 */
data class ForwardMessageV2(

    /**
     * Message ID. The id attribute value MUST be unique to the sender, across all messages they send.
     * This value MUST be used as the parent thread ID (pthid) for the response message that follows.
     * REQUIRED
     */
    val id: String,

    /**
     * The header conveying the DIDComm Message Type URI.
     * REQUIRED
     */
    val type: String,

    /**
     * Identifier(s) for recipients. MUST be an array of strings where each element is a valid DID or DID URL
     * that identifies a member of the message’s intended audience.
     * REQUIRED
     */
    val to: List<String>,

    /**
     * The identifier of the party to send the attached message to.
     * REQUIRED
     */
    val next: String,

    /**
     * The DIDComm message(s) to send to the party indicated in the next body attribute.
     * This content should be encrypted for the next recipient.
     * REQUIRED
     */
    val attachments: List<Attachment>,
) {
    internal constructor(builder: Builder): this(
        id = builder.id,
        type = builder.type,
        next = builder.next as String,
        to = builder.to as List<String>,
        attachments = builder.attachments as List<Attachment>,
    )

    companion object {
        fun fromMessage(msg: Message): ForwardMessageV2 {
            return Builder(msg.id, msg.type)
                .to(msg.to)
                .next(msg.body["next"] as? String)
                .attachments(msg.attachments)
                .build()
        }
    }

    fun toMessage(): Message {
        val body = mapOf("next" to next)
        return MessageBuilder(id, body, type)
            .to(to)
            .attachments(attachments)
            .build()
    }

    class Builder(
        val id: String,
        val type: String,
    ) {

        internal var next: String? = null
        internal var to: List<String>? = null
        internal var attachments: List<Attachment>? = null

        fun next(next: String?) = apply { this.next = next }
        fun to(recipients: List<String>?) = apply { this.to = recipients }
        fun attachments(attachments: List<Attachment>?) = apply { this.attachments = attachments }

        fun build(): ForwardMessageV2 {
            checkNotNull(next) { "No next" }
            checkNotNull(to) { "No recipients" }
            checkNotNull(attachments) { "No attachments" }
            return ForwardMessageV2(this)
        }
    }
}
