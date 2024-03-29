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

import com.google.gson.annotations.SerializedName
import id.walt.auditor.VerificationPolicy
import id.walt.common.prettyPrint
import mu.KotlinLogging
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.message.MessageBuilder
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.EndpointMessage
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.MessageExchange.Companion.PRESENTATION_ATTACHMENT_KEY
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.model.W3CVerifiablePresentation
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.PRESENT_PROOF_PROTOCOL_V3
import org.nessus.didcomm.util.MIME_TYPE_APPLICATION_JSON
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.jsonData
import org.nessus.didcomm.util.toValueMap
import java.time.Instant
import java.util.UUID
import java.util.concurrent.TimeUnit


/**
 * WACI DIDComm: Present Proof Protocol 3.0
 * https://github.com/decentralized-identity/waci-didcomm/blob/main/present_proof/present-proof-v3.md
 */
class PresentProofProtocolV3(mex: MessageExchange): Protocol<PresentProofProtocolV3>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = PRESENT_PROOF_PROTOCOL_V3.uri

    companion object {
        val PRESENT_PROOF_MESSAGE_TYPE_PROPOSE_PRESENTATION = "${PRESENT_PROOF_PROTOCOL_V3.uri}/propose-presentation"
        val PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION = "${PRESENT_PROOF_PROTOCOL_V3.uri}/request-presentation"
        val PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION = "${PRESENT_PROOF_PROTOCOL_V3.uri}/presentation"

        // [TODO] change to standard ack
        val PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION_ACK = "${PRESENT_PROOF_PROTOCOL_V3.uri}/ack"

        const val PRESENTATION_ATTACHMENT_FORMAT = "https://www.w3.org/TR/vc-data-model/"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.NESSUS)

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            PRESENT_PROOF_MESSAGE_TYPE_PROPOSE_PRESENTATION -> receivePresentationProposal(to)
            PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION -> receivePresentationRequest(to)
            PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION -> receivePresentation(to)
            PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION_ACK -> receivePresentationAck(to)
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

    /**
     * Propose Presentation
     *
     * Supported options
     * -----------------
     * goal_code: String
     * comment: String
     */
    fun sendPresentationProposal(
        prover: Wallet,
        verifierDid: Did,
        vcs: List<W3CVerifiableCredential>,
        domain: String? = null,
        challenge: String? = null,
        expirationDate: Instant? = null,
        options: Map<String, Any> = mapOf()
    ): PresentProofProtocolV3 {

        val pcon = mex.getConnection()
        check(pcon.myLabel == prover.alias) { "Unexpected prover: ${pcon.shortString()}" }
        check(pcon.theirDid == verifierDid) { "Unexpected verifier: ${pcon.shortString()}" }
        val proverDid = pcon.myDid

        val signedVp = custodian.createPresentation(
            vcs = vcs,
            holderDid = proverDid.uri,
            verifierDid = verifierDid.uri,
            domain = domain,
            challenge = challenge,
            expirationDate = expirationDate)

        prover.addVerifiablePresentation(signedVp)

        val jsonData = Attachment.Data.Json.parse(mapOf("json" to signedVp.toMap()))
        val vpAttachment = Attachment.Builder("${UUID.randomUUID()}", jsonData)
            .format(PRESENTATION_ATTACHMENT_FORMAT)
            .mediaType(MIME_TYPE_APPLICATION_JSON)
            .build()

        val id = "${UUID.randomUUID()}"
        val type = PRESENT_PROOF_MESSAGE_TYPE_PROPOSE_PRESENTATION

        val vpProposalMeta = ProposalMetaData.Builder()
            .goalCode(options["goal_code"] as? String)
            .comment(options["comment"] as? String)
            .build()

        val vpProposalMsg = MessageBuilder(id, vpProposalMeta.toMap(), type)
            .thid(id)
            .to(listOf(verifierDid.uri))
            .from(proverDid.uri)
            .attachments(listOf(vpAttachment))
            .build()

        mex.placeEndpointMessageFuture(PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION)

        mex.addMessage(EndpointMessage.Builder(vpProposalMsg).outbound().build())
        log.info { "Prover (${prover.alias}) creates presentation proposal: ${vpProposalMsg.encodeJson(true)}" }

        dispatchEncryptedMessage(pcon, vpProposalMsg) { packedEpm ->
            log.info { "Prover (${prover.alias}) sends presentation proposal: ${packedEpm.prettyPrint()}" }
        }

        return PresentProofProtocolV3(mex)
    }

    /**
     * Presentation Request
     *
     * Supported options
     * -----------------
     * goal_code: String
     * comment: String
     */
    fun sendPresentationRequest(
        verifier: Wallet,
        proverDid: Did,
        vc: W3CVerifiableCredential,
        options: Map<String, Any> = mapOf()
    ): PresentProofProtocolV3 {

        val mex = MessageExchange.findByWallet(verifier.alias).firstOrNull { it.getConnection().theirDid == proverDid }
        checkNotNull(mex) { "No message exchange for: ${proverDid.uri}"}

        val pcon = mex.getConnection()
        check(pcon.myLabel == verifier.alias) { "Unexpected verifier: ${pcon.shortString()}" }
        check(pcon.theirDid == proverDid) { "Unexpected prover: ${pcon.shortString()}" }
        val verifierDid = pcon.myDid

        val id = "${UUID.randomUUID()}"
        val type = PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION

        val jsonData = Attachment.Data.Json.parse(mapOf("json" to vc.toMap()))
        val attachment = Attachment.Builder("${UUID.randomUUID()}", jsonData)
            .format(PRESENTATION_ATTACHMENT_FORMAT)
            .mediaType(MIME_TYPE_APPLICATION_JSON)
            .build()

        val attachmentData = attachment.data.jsonData()
        checkNotNull(attachmentData) { "No attachment data" }

        val vpRequest = RequestMetaData.Builder(options)
            .willConfirm(true)
            .build()

        val vpRequestMsg = MessageBuilder(id, vpRequest.toMap(), type)
            .thid(id)
            .to(listOf(proverDid.uri))
            .from(verifierDid.uri)
            .attachments(listOf(attachment))
            .build()

        mex.addMessage(EndpointMessage.Builder(vpRequestMsg).outbound().build())
        log.info { "Verifier (${verifier.alias}) created presentation request: ${vpRequestMsg.encodeJson(true)}" }

        mex.placeEndpointMessageFuture(PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION)

        dispatchEncryptedMessage(pcon, vpRequestMsg) { packedEpm ->
            log.info { "Verifier (${verifier.alias}) sends presentation request: ${packedEpm.prettyPrint()}" }
        }

        return PresentProofProtocolV3(mex)
    }

    fun awaitPresentationRequest(prover: Wallet, verifierDid: Did, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): PresentProofProtocolV3 {
        val mex = MessageExchange.findByWallet(prover.alias).firstOrNull { it.getConnection().theirDid == verifierDid }
        checkNotNull(mex) { "No message exchange for: ${verifierDid.uri}"}
        mex.awaitEndpointMessage(PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION, timeout, unit)
        return this
    }

    fun awaitPresentation(verifier: Wallet, proverDid: Did, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): PresentProofProtocolV3 {
        val mex = MessageExchange.findByWallet(verifier.alias).firstOrNull { it.getConnection().theirDid == proverDid }
        checkNotNull(mex) { "No message exchange for: ${proverDid.uri}"}
        mex.awaitEndpointMessage(PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION, timeout, unit)
        return this
    }

    fun awaitPresentationAck(prover: Wallet, verifierDid: Did, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): PresentProofProtocolV3 {
        val mex = MessageExchange.findByWallet(prover.alias).firstOrNull { it.getConnection().theirDid == verifierDid }
        checkNotNull(mex) { "No message exchange for: ${verifierDid.uri}"}
        mex.awaitEndpointMessage(PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION_ACK, timeout, unit)
        return this
    }

    fun verifyPresentation(verifier: Wallet, policies: List<VerificationPolicy>): PresentProofProtocolV3 {

        val vp = mex.getAttachment(PRESENTATION_ATTACHMENT_KEY)
        checkNotNull(vp) { "No attached presentation" }

        // verify VP
        val vr = auditor.verify(vp, policies)
        check(vr.result) { "Verification failed" }

        return this
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun receivePresentationProposal(verifier: Wallet): PresentProofProtocolV3 {

        val pcon = mex.getConnection()
        val proverDid = pcon.theirDid

        val presentationProposalMsg = mex.last.body as Message
        mex.checkLastMessageType(PRESENT_PROOF_MESSAGE_TYPE_PROPOSE_PRESENTATION)

        log.info { "Verifier (${verifier.alias}) received presentation proposal: ${presentationProposalMsg.encodeJson(true)}" }

        // Extract the attached credential

        val attachmentsFormats = presentationProposalMsg.attachments?.map { it.format } ?: listOf(PRESENTATION_ATTACHMENT_FORMAT)
        check(PRESENTATION_ATTACHMENT_FORMAT in attachmentsFormats) { "Incompatible attachment formats: $attachmentsFormats" }

        val attachment = presentationProposalMsg.attachments?.firstOrNull { at -> at.format == null || at.format == PRESENTATION_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No presentation proposal attachment" }

        val attachmentData = attachment.data.jsonData()
        checkNotNull(attachmentData) { "No attachment data" }

        val proposedVp = W3CVerifiableCredential.fromMap(attachmentData)

        log.info { "Verifier (${verifier.alias}) accepts presentation proposal" }

        val metadata = presentationProposalMsg.body.toValueMap()
        return sendPresentationRequest(verifier, proverDid, proposedVp, metadata)
    }

    private fun receivePresentation(verifier: Wallet): PresentProofProtocolV3 {

        val presentationEpm = mex.last
        val presentationMsg = mex.last.body as Message
        mex.checkLastMessageType(PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION)

        val attachmentsFormats = presentationMsg.attachments?.map { it.format } ?: listOf(PRESENTATION_ATTACHMENT_FORMAT)
        check(PRESENTATION_ATTACHMENT_FORMAT in attachmentsFormats) { "Incompatible attachment formats: $attachmentsFormats" }

        val attachment = presentationMsg.attachments?.firstOrNull { at -> at.format == null || at.format == PRESENTATION_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No presentation attachment" }

        val attachmentData = attachment.data.jsonData()
        checkNotNull(attachmentData) { "No attachment data" }

        val vp = W3CVerifiablePresentation.fromMap(attachmentData)
        mex.putAttachment(PRESENTATION_ATTACHMENT_KEY, vp)
        verifier.addVerifiablePresentation(vp)

        if (mex.hasEndpointMessageFuture(PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION))
            mex.completeEndpointMessageFuture(PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION, mex.last)

        log.info { "Verifier (${verifier.alias}) accepts presentation: ${presentationMsg.encodeJson(true)}" }

        return sendPresentationAck(verifier, presentationEpm)
    }

    private fun receivePresentationRequest(prover: Wallet): PresentProofProtocolV3 {

        val vpRequestMsg = mex.last.body as Message
        mex.checkLastMessageType(PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION)

        val pcon = mex.getConnection()
        val verifierDid = pcon.theirDid

        log.info { "Prover (${prover.alias}) received presentation request: ${vpRequestMsg.encodeJson(true)}" }

        mex.placeEndpointMessageFuture(PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION_ACK)

        if (mex.hasEndpointMessageFuture(PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION))
            mex.completeEndpointMessageFuture(PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION, mex.last)

        return sendPresentation(prover, verifierDid)
    }

    private fun receivePresentationAck(prover: Wallet): PresentProofProtocolV3 {

        val ackMsg = mex.last.body as Message
        mex.checkLastMessageType(PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION_ACK)

        log.info { "Prover (${prover.alias}) received presentation ack: ${ackMsg.encodeJson(true)}" }

        mex.completeEndpointMessageFuture(PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION_ACK, mex.last)
        return this
    }

    private fun sendPresentation(prover: Wallet, verifierDid: Did): PresentProofProtocolV3 {

        val pcon = mex.getConnection()
        val proverDid = pcon.myDid

        val vpRequestMsg = mex.last.body as Message
        mex.checkLastMessageType(PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION)

        var attachment = vpRequestMsg.attachments?.firstOrNull { at -> at.format == null || at.format == PRESENTATION_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No presentation attachment" }

        val attachmentData = attachment.data.jsonData()
        checkNotNull(attachmentData) { "No attachment data" }

        // If this is already a VP, we assume that the presentation request
        // already contains our proposal and that the verifier accepted it
        val maybeVp = W3CVerifiableCredential.fromMap(attachmentData)

        if (!maybeVp.types.contains("VerifiablePresentation")) {

            val templates = maybeVp.types.filter { it != "VerifiableCredential" }
            check(templates.isNotEmpty()) { "No template from VC type: ${maybeVp.types}" }
            check(templates.size == 1) { "Multiple VC types not supported: $templates" }
            val template = templates[0]

            val vcs = prover.findVerifiableCredentialsByType(template)
            check(vcs.isNotEmpty()) { "Prover ${prover.alias} holds no credential of type: $template" }
            check(vcs.size == 1) { "Prover ${prover.alias} holds multiple credentials of type: $template" }

            val signedVp = custodian.createPresentation(
                vcs = listOf(vcs[0]),
                holderDid = proverDid.uri,
                verifierDid = verifierDid.uri,
            )

            val jsonData = Attachment.Data.Json.parse(mapOf("json" to signedVp.toMap()))
            attachment = Attachment.Builder("${UUID.randomUUID()}", jsonData)
                .format(PRESENTATION_ATTACHMENT_FORMAT)
                .mediaType(MIME_TYPE_APPLICATION_JSON)
                .build()
        }

        val id = "${UUID.randomUUID()}"
        val type = PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION

        val vpRequestMeta = RequestMetaData.fromMap(vpRequestMsg.toJSONObject())
        val vpMeta = PresentationMetaData.Builder()
            .goalCode(vpRequestMeta.goalCode)
            .build()

        val vpMsg = MessageBuilder(id, vpMeta.toMap(), type)
            .thid(vpRequestMsg.id)
            .to(listOf(verifierDid.uri))
            .from(proverDid.uri)
            .attachments(listOf(attachment))
            .build()

        mex.addMessage(EndpointMessage.Builder(vpMsg).outbound().build())
        log.info { "Prover (${prover.alias}) created presentation: ${vpMsg.encodeJson(true)}" }

        dispatchEncryptedMessage(pcon, vpMsg) { packedEpm ->
            log.info { "Prover (${prover.alias}) sends presentation: ${packedEpm.prettyPrint()}" }
        }

        return this
    }

    private fun sendPresentationAck(verifier: Wallet, presentationEpm: EndpointMessage): PresentProofProtocolV3 {
        presentationEpm.checkMessageType(PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION)

        val presentationMsg = mex.last.body as Message

        val pcon = mex.getConnection()
        val (verifierDid, proverDid) = Pair(pcon.myDid, pcon.theirDid)

        val id = "${UUID.randomUUID()}"
        val type = PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION_ACK

        val vpAckMsg = MessageBuilder(id, mapOf(), type)
            .thid(presentationMsg.id)
            .to(listOf(proverDid.uri))
            .from(verifierDid.uri)
            .build()

        mex.addMessage(EndpointMessage.Builder(vpAckMsg).outbound().build())
        log.info { "Verifier (${verifier.alias}) creates presentation ack: ${vpAckMsg.encodeJson(true)}" }

        dispatchEncryptedMessage(pcon, vpAckMsg) { packedEpm ->
            log.info { "Verifier (${verifier.alias}) sends presentation ack: ${packedEpm.prettyPrint()}" }
        }

        return this
    }

    // Types -----------------------------------------------------------------------------------------------------------

    data class ProposalMetaData(

        /**
         * Optional field that indicates the goal of the message sender
         */
        @SerializedName("goal_code")
        val goalCode: String?,

        /**
         * Optional field that provides some human readable information about the proposed presentation.
         */
        @SerializedName("comment")
        val comment: String?,
    ) {
        companion object {

            fun fromMap(body: Map<String, Any?>): ProposalMetaData {
                val builder = Builder()
                body["goal_code"]?.also { builder.goalCode(it as String) }
                body["comment"]?.also { builder.comment(it as String) }
                return builder.build()
            }
        }

        fun toMap() = encodeJson().decodeJson()

        class Builder {
            private var goalCode: String? = null
            private var comment: String? = null

            fun goalCode(goalCode: String?) = apply { this.goalCode = goalCode }
            fun comment(comment: String?) = apply { this.comment = comment }

            fun build(): ProposalMetaData {
                return ProposalMetaData(goalCode, comment)
            }
        }
    }

    data class RequestMetaData(

        /**
         * Optional field that indicates the goal of the message sender
         */
        @SerializedName("goal_code")
        val goalCode: String?,

        /**
         * Optional field that provides some human readable information about this request for a presentation.
         */
        @SerializedName("comment")
        val comment: String?,

        /**
         * An optional field (defaults to false) to indicate that the verifier will or will not send a post-presentation
         * confirmation ack message.
         */
        @SerializedName("will_confirm")
        val willConfirm: Boolean,
    ) {
        companion object {
            fun fromMap(body: Map<String, Any?>) = Builder(body).build()
        }

        fun toMap() = encodeJson().decodeJson()

        class Builder(body: Map<String, Any?> = mapOf()) {

            private var goalCode: String? = null
            private var comment: String? = null
            private var willConfirm: Boolean = false

            init {
                body["goal_code"]?.also { goalCode(it as String) }
                body["comment"]?.also { comment(it as String) }
                body["will_confirm"]?.also { willConfirm("$it".toBoolean()) }
            }

            fun goalCode(goalCode: String?) = apply { this.goalCode = goalCode }
            fun comment(comment: String?) = apply { this.comment = comment }
            fun willConfirm(willConfirm: Boolean) = apply { this.willConfirm = willConfirm }
            fun build(): RequestMetaData {
                return RequestMetaData(goalCode, comment, willConfirm)
            }
        }
    }

    data class PresentationMetaData(

        /**
         * Optional field that indicates the goal of the message sender
         */
        @SerializedName("goal_code")
        val goalCode: String?,

        /**
         * Optional field that provides some human readable information about the presentation.
         */
        @SerializedName("comment")
        val comment: String?,
    ) {
        companion object {

            fun fromMap(body: Map<String, Any?>): PresentationMetaData {
                val builder = Builder()
                body["goal_code"]?.also { builder.goalCode(it as String) }
                body["comment"]?.also { builder.comment(it as String) }
                return builder.build()
            }
        }

        fun toMap() = encodeJson().decodeJson()

        class Builder {
            private var goalCode: String? = null
            private var comment: String? = null

            fun goalCode(goalCode: String?) = apply { this.goalCode = goalCode }
            fun comment(comment: String?) = apply { this.comment = comment }

            fun build(): PresentationMetaData {
                return PresentationMetaData(goalCode, comment)
            }
        }
    }
}