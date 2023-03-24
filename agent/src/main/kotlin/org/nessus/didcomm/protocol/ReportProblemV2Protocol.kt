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
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.message.MessageBuilder
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.REPORT_PROBLEM_PROTOCOL_V2

/**
 * Nessus DIDComm: Report Problem 2.0
 * https://identity.foundation/didcomm-messaging/spec/#problem-reports
 */
class ReportProblemProtocolV2(mex: MessageExchange): Protocol<ReportProblemProtocolV2>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = REPORT_PROBLEM_PROTOCOL_V2.uri

    companion object {
        val REPORT_PROBLEM_MESSAGE_TYPE_PROBLEM_REPORT_V2 = "${REPORT_PROBLEM_PROTOCOL_V2.uri}/problem-report"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.ACAPY, AgentType.NESSUS)

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

}

/**
 * Problem Report
 *
 * {
 *   "type": "https://didcomm.org/report-problem/2.0/problem-report",
 *   "id": "7c9de639-c51c-4d60-ab95-103fa613c805",
 *   "pthid": "1e513ad4-48c9-444e-9e7e-5b8b45c5e325",
 *   "ack": ["1e513ad4-48c9-444e-9e7e-5b8b45c5e325"],
 *   "body": {
 *     "code": "e.p.xfer.cant-use-endpoint",
 *     "comment": "Unable to use the {1} endpoint for {2}.",
 *     "args": [
 *       "https://agents.r.us/inbox",
 *       "did:sov:C805sNYhMrjHiqZDTUASHg"
 *     ],
 *     "escalate_to": "mailto:admin@foo.org"
 *   }
 * }
 */
data class ProblemReportV2(

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
     * The value is the thid of the thread in which the problem occurred.
     * REQUIRED
     */
    val pthid: String,

    /**
     * Should be included if the problem in question was triggered directly by a preceding message.
     * OPTIONAL
     */
    val ack: List<String>?,

    /**
     * Categorizes what went wrong.
     * https://identity.foundation/didcomm-messaging/spec/#problem-codes
     * REQUIRED
     */
    val code: String,

    /**
     * Contains human-friendly text describing the problem.
     *
     * If the field is present, the text MUST be statically associated with code, meaning that each time circumstances
     * trigger a problem with the same code, the value of comment will be the same.
     * OPTIONAL
     */
    val comment: String?,

    /**
     * Contains situation-specific values that are interpolated into the value of comment,
     * providing extra detail for human readers. Each unique problem code has a definition for the args it takes.
     *
     * If the field is present, the text MUST be statically associated with code, meaning that each time circumstances
     * trigger a problem with the same code, the value of comment will be the same.
     * OPTIONAL
     */
    val args: List<String>?,

    /**
     * Provides a URI where additional help on the issue can be received.
     */
    val escalateTo: String?,
) {
    internal constructor(builder: Builder): this(
        id = builder.id,
        type = builder.type,
        pthid = builder.pthid,
        ack = builder.ack,
        code = builder.code!!,
        comment = builder.comment,
        args = builder.args,
        escalateTo = builder.escalateTo,
    )

    companion object {

        @Suppress("UNCHECKED_CAST")
        fun fromMessage(msg: Message): ProblemReportV2 {
            return Builder(msg.id, msg.type, msg.pthid!!)
                .ack(msg.body["ack"] as? List<String>)
                .args(msg.body["args"] as? List<String>)
                .code(msg.body["code"] as? String)
                .comment(msg.body["comment"] as? String)
                .escalateTo(msg.body["escalate_to"] as? String)
                .build()
        }
    }

    fun toMessage(): Message {
        val body = LinkedHashMap<String, Any>()
        body["code"] = code
        ack?.also { body["ack"] = ack }
        args?.also { body["args"] = args }
        comment?.also { body["comment"] = comment }
        escalateTo?.also { body["escalate_to"] = escalateTo }
        return MessageBuilder(id, body, type).build()
    }

    class Builder(
        val id: String,
        val type: String,
        val pthid: String,
    ) {

        internal var ack: List<String>? = null
        internal var args: List<String>? = null
        internal var code: String? = null
        internal var comment: String? = null
        internal var escalateTo: String? = null

        fun ack(ack: List<String>?) = apply { this.ack = ack?.toList() }
        fun args(args: List<String>?) = apply { this.args = args?.toList() }
        fun code(code: String?) = apply { this.code = code }
        fun comment(comment: String?) = apply { this.comment = comment }
        fun escalateTo(escalateTo: String?) = apply { this.escalateTo = escalateTo }

        fun build(): ProblemReportV2 {
            checkNotNull(code) { "No code" }
            return ProblemReportV2(this)
        }
    }
}
