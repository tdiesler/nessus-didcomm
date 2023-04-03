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
import id.walt.common.prettyPrint
import mu.KotlinLogging
import org.didcommx.didcomm.common.Typ
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.message.MessageBuilder
import org.didcommx.didcomm.model.PackEncryptedParams
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_ID
import org.nessus.didcomm.protocol.EndpointMessage.Companion.MESSAGE_HEADER_TYPE
import org.nessus.didcomm.service.PRESENT_PROOF_PROTOCOL_V3
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.jsonData
import java.time.Instant
import java.util.UUID
import java.util.concurrent.TimeUnit


/**
 * WACI DIDComm: Present Proof Protocol 3.0
 * https://github.com/decentralized-identity/waci-didcomm/blob/main/present_proof/present-proof-v3.md
 */
class PresentProofV3Protocol(mex: MessageExchange): Protocol<PresentProofV3Protocol>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = PRESENT_PROOF_PROTOCOL_V3.uri

    companion object {
        val PRESENT_PROOF_MESSAGE_TYPE_PROPOSE_PRESENTATION = "${PRESENT_PROOF_PROTOCOL_V3.uri}/propose-presentation"
        val PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION = "${PRESENT_PROOF_PROTOCOL_V3.uri}/request-presentation"
        val PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION = "${PRESENT_PROOF_PROTOCOL_V3.uri}/presentation"

        // [TODO] change to standard ack
        val PRESENT_PROOF_MESSAGE_TYPE_ACK = "${PRESENT_PROOF_PROTOCOL_V3.uri}/ack"

        const val PRESENTATION_ATTACHMENT_FORMAT = "https://www.w3.org/TR/vc-data-model/"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.NESSUS)

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            PRESENT_PROOF_MESSAGE_TYPE_PROPOSE_PRESENTATION -> receivePresentationProposal(to)
            PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION -> receivePresentationRequest(to)
            PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION -> receivePresentation(to)
            PRESENT_PROOF_MESSAGE_TYPE_ACK -> receivePresentationAck(to)
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
        verifierDid: Did,
        prover: Wallet,
        vcs: List<W3CVerifiableCredential>,
        domain: String? = null,
        challenge: String? = null,
        expirationDate: Instant? = null,
        options: Map<String, Any> = mapOf()
    ): PresentProofV3Protocol {

        val mex = MessageExchange.findByWallet(prover.name)
            .first { it.getConnection().theirDid == verifierDid }

        val pcon = mex.getConnection()
        val proverDid = pcon.myDid

        val signedVp = custodian.createPresentation(
            vcs = vcs.toTypedArray(),
            holderDid = proverDid.uri,
            verifierDid = verifierDid.uri,
            domain = domain,
            challenge = challenge,
            expirationDate = expirationDate)

        prover.addVerifiableCredential(signedVp)

        val jsonData = Attachment.Data.Json.parse(mapOf("json" to signedVp.jsonObject))
        val vpAttachment = Attachment.Builder("${UUID.randomUUID()}", jsonData)
            .format(PRESENTATION_ATTACHMENT_FORMAT)
            .mediaType("application/json")
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

        log.info { "Prover (${prover.name}) proposes presentation: ${vpProposalMsg.encodeJson(true)}" }

        val epm = EndpointMessage.Builder(vpProposalMsg).outbound().build()
        mex.addMessage(epm)

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(vpProposalMsg, verifierDid.uri)
                .signFrom(proverDid.uri)
                .from(proverDid.uri)
                .build()
        )

        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage.Builder(packedMessage, mapOf(
                MESSAGE_HEADER_ID to "${vpProposalMsg.id}.packed",
                MESSAGE_HEADER_TYPE to Typ.Encrypted.typ))
            .outbound().build()

        log.info { "Prover (${prover.name}) sends credential presentation: ${vpProposalMsg.encodeJson(true)}" }

        mex.placeEndpointMessageFuture(PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION)

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
        return PresentProofV3Protocol(mex)
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
        vp: W3CVerifiableCredential
    ): PresentProofV3Protocol {
        check(vp.isVerifiablePresentation) { "Not a verifiable presentation: ${vp.shortString()}" }

        val mex = MessageExchange.findByWallet(verifier.name)
            .first { it.getConnection().theirDid == proverDid }

        val pcon = mex.getConnection()
        val verifierDid = pcon.myDid

        val presentationProposalEpm = mex.last
        val presentationProposalMsg = mex.last.body as Message
        presentationProposalEpm.checkMessageType(PRESENT_PROOF_MESSAGE_TYPE_PROPOSE_PRESENTATION)

        // Extract the proposal data from the Message

        val proposalMeta = ProposalMetaData.fromMap(presentationProposalMsg.body)

        // Extract the attached credential

        val attachmentsFormats = presentationProposalMsg.attachments?.map { it.format } ?: listOf(PRESENTATION_ATTACHMENT_FORMAT)
        check(PRESENTATION_ATTACHMENT_FORMAT in attachmentsFormats) { "Incompatible attachment formats: $attachmentsFormats" }

        val attachment = presentationProposalMsg.attachments?.firstOrNull { at -> at.format == null || at.format == PRESENTATION_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No presentation proposal attachment" }

        val attachmentData = attachment.data.jsonData()
        checkNotNull(attachmentData) { "No attachment data" }

        val id = "${UUID.randomUUID()}"
        val type = PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION

        val vpRequest = RequestMetaData.Builder()
            .goalCode(proposalMeta.goalCode)
            .willConfirm(true)
            .build()

        val presentationRequestMsg = MessageBuilder(id, vpRequest.toMap(), type)
            .thid(id)
            .to(listOf(proverDid.uri))
            .from(verifierDid.uri)
            .attachments(listOf(attachment))
            .build()

        log.info { "Verifier (${verifier.name}) created presentation request: ${presentationRequestMsg.encodeJson(true)}" }

        val epm = EndpointMessage.Builder(presentationRequestMsg).outbound().build()
        mex.addMessage(epm)

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(presentationRequestMsg, proverDid.uri)
                .signFrom(verifierDid.uri)
                .from(verifierDid.uri)
                .build()
        )

        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage.Builder(packedMessage, mapOf(
                MESSAGE_HEADER_ID to "${presentationRequestMsg.id}.packed",
                MESSAGE_HEADER_TYPE to Typ.Encrypted.typ))
            .outbound()
            .build()
        log.info { "Verifier (${verifier.name}) sends presentation request: ${packedEpm.prettyPrint()}" }

        mex.placeEndpointMessageFuture(PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION)

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
        return PresentProofV3Protocol(mex)
    }

    fun awaitPresentationRequest(prover: Wallet, verifierDid: Did, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): PresentProofV3Protocol {
        val mex = MessageExchange.findByWallet(prover.name).first { it.getConnection().theirDid == verifierDid }
        mex.awaitEndpointMessage(PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION, timeout, unit)
        return this
    }

    /**
     * Send Presentation
     */
    fun sendPresentation(prover: Wallet, verifierDid: Did): PresentProofV3Protocol {

        val mex = MessageExchange.findByWallet(prover.name)
            .first { it.getConnection().theirDid == verifierDid }

        val pcon = mex.getConnection()
        val issuerDid = pcon.myDid

        val vpRequestEpm = mex.last
        val vpRequestMsg = mex.last.body as Message
        vpRequestEpm.checkMessageType(PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION)

        val id = "${UUID.randomUUID()}"
        val type = PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION

        val attachment = vpRequestMsg.attachments?.firstOrNull { at -> at.format == null || at.format == PRESENTATION_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No presentation attachment" }

        val vpRequestMeta = RequestMetaData.fromMap(vpRequestMsg.toJSONObject())
        val vpMeta = PresentationMetaData.Builder()
            .goalCode(vpRequestMeta.goalCode)
            .build()

        val vpMsg = MessageBuilder(id, vpMeta.toMap(), type)
            .thid(vpRequestMsg.id)
            .to(listOf(verifierDid.uri))
            .from(issuerDid.uri)
            .attachments(listOf(attachment))
            .build()

        val epm = EndpointMessage.Builder(vpMsg).outbound().build()
        mex.addMessage(epm)

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(vpMsg, verifierDid.uri)
                .signFrom(issuerDid.uri)
                .from(issuerDid.uri)
                .build()
        )

        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage.Builder(packedMessage, mapOf(
                MESSAGE_HEADER_ID to "${vpMsg.id}.packed",
                MESSAGE_HEADER_TYPE to Typ.Encrypted.typ))
            .outbound()
            .build()

        log.info { "Prover (${prover.name}) sends presentation: ${packedEpm.prettyPrint()}" }

        mex.placeEndpointMessageFuture(PRESENT_PROOF_MESSAGE_TYPE_ACK)

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
        return this
    }

    fun awaitPresentationAck(prover: Wallet, verifierDid: Did, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): PresentProofV3Protocol {
        val mex = MessageExchange.findByWallet(prover.name).first { it.getConnection().theirDid == verifierDid }
        mex.awaitEndpointMessage(PRESENT_PROOF_MESSAGE_TYPE_ACK, timeout, unit)
        return this
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun receivePresentationProposal(verifier: Wallet): PresentProofV3Protocol {

        val pcon = mex.getConnection()
        val proverDid = pcon.theirDid

        val presentationProposalEpm = mex.last
        val presentationProposalMsg = mex.last.body as Message
        presentationProposalEpm.checkMessageType(PRESENT_PROOF_MESSAGE_TYPE_PROPOSE_PRESENTATION)

        log.info { "Verifier (${verifier.name}) received presentation proposal: ${presentationProposalMsg.encodeJson(true)}" }

        // Extract the attached credential

        val attachmentsFormats = presentationProposalMsg.attachments?.map { it.format } ?: listOf(PRESENTATION_ATTACHMENT_FORMAT)
        check(PRESENTATION_ATTACHMENT_FORMAT in attachmentsFormats) { "Incompatible attachment formats: $attachmentsFormats" }

        val attachment = presentationProposalMsg.attachments?.firstOrNull { at -> at.format == null || at.format == PRESENTATION_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No presentation proposal attachment" }

        val attachmentData = attachment.data.jsonData()
        checkNotNull(attachmentData) { "No attachment data" }

        val proposedVp = W3CVerifiableCredential.fromJson(attachmentData)

        log.info { "Verifier (${verifier.name}) accepts presentation proposal" }

        return sendPresentationRequest(verifier, proverDid, proposedVp)
    }

    private fun receivePresentation(verifier: Wallet): PresentProofV3Protocol {

        val presentationEpm = mex.last
        val presentationMsg = mex.last.body as Message
        presentationEpm.checkMessageType(PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION)

        val attachmentsFormats = presentationMsg.attachments?.map { it.format } ?: listOf(PRESENTATION_ATTACHMENT_FORMAT)
        check(PRESENTATION_ATTACHMENT_FORMAT in attachmentsFormats) { "Incompatible attachment formats: $attachmentsFormats" }

        val attachment = presentationMsg.attachments?.firstOrNull { at -> at.format == null || at.format == PRESENTATION_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No presentation attachment" }

        log.info { "Verifier (${verifier.name}) accepts presentation: ${presentationMsg.encodeJson(true)}" }

        return sendPresentationAck(verifier, presentationEpm)
    }

    private fun sendPresentationAck(verifier: Wallet, presentationEpm: EndpointMessage): PresentProofV3Protocol {

        val pcon = mex.getConnection()
        val (verifierDid, proverDid) = Pair(pcon.myDid, pcon.theirDid)

        val presentationMsg = mex.last.body as Message
        presentationEpm.checkMessageType(PRESENT_PROOF_MESSAGE_TYPE_PRESENTATION)

        val id = "${UUID.randomUUID()}"
        val type = PRESENT_PROOF_MESSAGE_TYPE_ACK

        val credentialRequestMsg = MessageBuilder(id, mapOf(), type)
            .thid(presentationMsg.id)
            .to(listOf(proverDid.uri))
            .from(verifierDid.uri)
            .build()

        val epm = EndpointMessage.Builder(credentialRequestMsg).outbound().build()
        mex.addMessage(epm)

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(credentialRequestMsg, proverDid.uri)
                .signFrom(verifierDid.uri)
                .from(verifierDid.uri)
                .build()
        )

        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage.Builder(
            packedMessage, mapOf(
                MESSAGE_HEADER_ID to "${credentialRequestMsg.id}.packed",
                MESSAGE_HEADER_TYPE to Typ.Encrypted.typ
            )).outbound().build()

        log.info { "Verifier (${verifier.name}) sends presentation ack: ${packedEpm.prettyPrint()}" }

        val proverMex = MessageExchange.findByVerkey(proverDid.verkey)
        proverMex?.placeEndpointMessageFuture(PRESENT_PROOF_MESSAGE_TYPE_ACK)

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
        return this
    }

    private fun receivePresentationRequest(prover: Wallet): PresentProofV3Protocol {

        val vpRequestEpm = mex.last
        val vpRequestMsg = mex.last.body as Message
        vpRequestEpm.checkMessageType(PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION)

        log.info { "Prover (${prover.name}) received presentation request: ${vpRequestMsg.encodeJson(true)}" }

        mex.completeEndpointMessageFuture(PRESENT_PROOF_MESSAGE_TYPE_REQUEST_PRESENTATION, mex.last)

        val pcon = mex.getConnection()
        val holderDid = pcon.theirDid

        return sendPresentation(prover, holderDid)
    }

    private fun receivePresentationAck(prover: Wallet): PresentProofV3Protocol {

        val ackEpm = mex.last
        val ackMsg = mex.last.body as Message
        ackEpm.checkMessageType(PRESENT_PROOF_MESSAGE_TYPE_ACK)

        log.info { "Prover (${prover.name}) received presentation ack: ${ackMsg.encodeJson(true)}" }

        mex.completeEndpointMessageFuture(PRESENT_PROOF_MESSAGE_TYPE_ACK, mex.last)
        return this
    }

    // Types -----------------------------------------------------------------------------------------------------------

    data class PreviewAttribute(
        /**
         * Mandatory "name" key maps to the attribute name as a string
         */
        val name: String,

        /**
         * The mandatory value holds the attribute value:
         *
         * If media_type is missing (null), then value is a string.
         *
         * If media_type is not null, then value is always a base64url-encoded string that represents a binary BLOB,
         *   and media_type tells how to interpret the BLOB after base64url-decoding.
         */
        val value: Any,

        /**
         * Optional media_type advises the issuer how to render a binary attribute,
         * to judge its content for applicability before issuing a credential containing it.
         */
        @SerializedName("media_type")
        val mediaType: String? = null,
    ) {
        companion object {
            fun fromJson(json: String): PreviewAttribute {
                return gson.fromJson(json, PreviewAttribute::class.java)
            }
        }
    }

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

            fun fromMap(body: Map<String, Any?>): RequestMetaData {
                val builder = Builder()
                body["goal_code"]?.also { builder.goalCode(it as String) }
                body["comment"]?.also { builder.comment(it as String) }
                body["will_confirm"]?.also { builder.willConfirm("$it".toBoolean()) }
                return builder.build()
            }
        }

        fun toMap() = encodeJson().decodeJson()

        class Builder {
            private var goalCode: String? = null
            private var comment: String? = null
            private var willConfirm: Boolean = false

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