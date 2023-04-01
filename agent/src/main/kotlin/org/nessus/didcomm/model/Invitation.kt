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
package org.nessus.didcomm.model

import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.message.MessageBuilder
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.service.ModelService
import org.nessus.didcomm.util.decodeJson
import java.io.InputStreamReader
import java.net.URL

/**
 * [Out of Band Invitation]https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages
 *
 * {
 *   "type": "https://didcomm.org/out-of-band/2.0/invitation",
 *   "id": "<id used for context as pthid>",
 *   "from":"<sender's did>",
 *   "body": {
 *     "goal_code": "issue-vc",
 *     "goal": "To issue a Faber College Graduate credential",
 *     "accept": [
 *       "didcomm/v2",
 *       "didcomm/aip2;env=rfc587"
 *     ],
 *   },
 *   "attachments": [
 *     {
 *         "id": "request-0",
 *         "mime_type": "application/json",
 *         "data": {
 *             "json": "<json of protocol message>"
 *         }
 *     }
 *   ]
 * }
 */
data class Invitation(

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
     * The DID representing the sender to be used by recipients for future interactions.
     * REQUIRED
     */
    val from: String,

    /**
     * A self-attested code the receiver may want to display to the user or use in automatically deciding what to do with the out-of-band message.
     * OPTIONAL
     */
    val goalCode: String?,

    /**
     * A self-attested string that the receiver may want to display to the user about the context-specific goal of the out-of-band message.
     * OPTIONAL
     */
    val goal: String?,

    /**
     * An array of media types in the order of preference for sending a message to the endpoint.
     * These identify a profile of DIDComm Messaging that the endpoint supports.
     * OPTIONAL
     */
    val accept: List<String>?,

    /**
     * An array of attachments that will contain the invitation messages in order of preference that the receiver can use in responding to the message.
     * Each message in the array is a rough equivalent of the others, and all are in pursuit of the stated goal and goal_code.
     * Only one of the messages should be chosen and acted upon.
     * OPTIONAL
     */
    val attachments: List<Attachment>?,
) {
    internal constructor(builder: Builder): this(
        id = builder.id,
        type = builder.type,
        from = builder.from,
        goalCode = builder.goalCode,
        goal = builder.goal,
        accept = builder.accept,
        attachments = builder.attachments,
    )

    @Suppress("UNCHECKED_CAST")
    companion object {
        val DEFAULT_ACCEPT = listOf("didcomm/v2") //, "didcomm/aip2;env=rfc587")

        fun fromUrl(url: URL): Invitation {
            return with(InputStreamReader(url.openStream())) {
                fromMessage(Message.parse(readText().decodeJson()))
            }
        }

        fun fromMessage(msg: Message): Invitation {
            requireNotNull(msg.from) { "No from" }
            return Builder(msg.id, msg.type, msg.from!!)
                .goalCode(msg.body["goal_code"] as? String)
                .goal(msg.body["goal"] as? String)
                .accept(msg.body["accept"] as? List<String>)
                .attachments(msg.attachments)
                .build()
        }
    }

    private val didService get() = DidService.getService()
    private val modelService get() = ModelService.getService()

    val diddoc: DidDoc
        get() = run {
        val invitationDidDoc = attachments
            ?.firstOrNull { it.mediaType == DID_DOCUMENT_MEDIA_TYPE }
            ?.let { DidDoc.fromAttachment(it) }
            ?:let { didService.resolveDidDoc(from) }
        checkNotNull(invitationDidDoc) { "No invitation DidDoc" }
    }

    fun invitationKey(): String {
        return recipientDid().verkey
    }

    fun recipientDid(): Did {
        val recipientDid = didService.loadOrResolveDid(from)
        checkNotNull(recipientDid) { "Cannot resolve did: $from" }
        return recipientDid
    }

    fun recipientServiceEndpoint(): String {
        return diddoc.serviceEndpoint as String
    }

    fun toMessage(): Message {
        val body = LinkedHashMap<String, Any>()
        goalCode?.also { body["goal_code"] = goalCode }
        goal?.also { body["goal"] = goal }
        accept?.also { body["accept"] = accept }
        return MessageBuilder(id, body, type)
            .from(from)
            .attachments(attachments)
            .build()
    }

    fun shortString(): String {
        return "${recipientDid().uri} [key=${invitationKey()}, url=${recipientServiceEndpoint()}]"
    }

    class Builder(
        val id: String,
        val type: String,
        val from: String) {

        internal var goalCode: String? = null
            private set

        internal var goal: String? = null
            private set

        internal var accept: List<String>? = null
            private set

        internal var attachments: List<Attachment>? = null
            private set

        fun goalCode(goalCode: String?) = apply { this.goalCode = goalCode }
        fun goal(goal: String?) = apply { this.goal = goal }
        fun accept(accept: List<String>?) = apply { this.accept = accept?.toList() }
        fun attachments(attachments: List<Attachment>?) = apply { this.attachments = attachments?.toList() }

        fun build(): Invitation {
            return Invitation(this)
        }
    }
}
