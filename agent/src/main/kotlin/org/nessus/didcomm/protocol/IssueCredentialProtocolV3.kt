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
import id.walt.credentials.w3c.VerifiableCredential
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import mu.KotlinLogging
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.message.MessageBuilder
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.EndpointMessage
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.ISSUE_CREDENTIAL_PROTOCOL_V3
import org.nessus.didcomm.util.JSON_MIME_TYPE
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.jsonData
import org.nessus.didcomm.util.unionMap
import java.util.UUID
import java.util.concurrent.TimeUnit


/**
 * WACI DIDComm: Issue Credential Protocol 3.0
 * https://github.com/decentralized-identity/waci-didcomm/tree/main/issue_credential
 */
class IssueCredentialProtocolV3(mex: MessageExchange): Protocol<IssueCredentialProtocolV3>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = ISSUE_CREDENTIAL_PROTOCOL_V3.uri

    companion object {
        val ISSUE_CREDENTIAL_MESSAGE_TYPE_PROPOSE_CREDENTIAL = "${ISSUE_CREDENTIAL_PROTOCOL_V3.uri}/propose-credential"
        val ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL = "${ISSUE_CREDENTIAL_PROTOCOL_V3.uri}/offer-credential"
        val ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL = "${ISSUE_CREDENTIAL_PROTOCOL_V3.uri}/request-credential"
        val ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL = "${ISSUE_CREDENTIAL_PROTOCOL_V3.uri}/issue-credential"

        // [TODO] change to standard ack
        val ISSUE_CREDENTIAL_MESSAGE_TYPE_CREDENTIAL_ACK = "${ISSUE_CREDENTIAL_PROTOCOL_V3.uri}/ack"

        const val CREDENTIAL_ATTACHMENT_FORMAT = "https://www.w3.org/TR/vc-data-model/"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.NESSUS)

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            ISSUE_CREDENTIAL_MESSAGE_TYPE_PROPOSE_CREDENTIAL -> receiveCredentialProposal(to)
            ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL -> receiveCredentialOffer(to)
            ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL -> receiveCredentialRequest(to)
            ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL -> receiveCredential(to)
            ISSUE_CREDENTIAL_MESSAGE_TYPE_CREDENTIAL_ACK -> receiveCredentialAck(to)
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

    /**
     * Propose Credential
     *
     * Supported options
     * -----------------
     * goal_code: String
     * comment: String
     */
    fun sendCredentialProposal(
        holder: Wallet,
        issuerDid: Did,
        template: String,
        subjectData: Map<String, Any>,
        options: Map<String, Any> = mapOf()
    ): IssueCredentialProtocolV3 {

        val mex = MessageExchange.findByWallet(holder.name).firstOrNull { it.getConnection().theirDid == issuerDid }
        checkNotNull(mex) { "No message exchange for: ${issuerDid.uri}"}

        val pcon = mex.getConnection()
        val holderDid = pcon.myDid

        val credentialTemplate = """{
            "id": "urn:uuid:${UUID.randomUUID()}",
            "issuer": "${issuerDid.uri}",
            "credentialSubject": {
                "id": "${holderDid.uri}"
            }
        }""".decodeJson()

        val subjectTemplate = """{
            "credentialSubject": ${subjectData.encodeJson()}
        }""".decodeJson()

        val mergedData = credentialTemplate.unionMap(subjectTemplate)

        val unsignedVc = W3CVerifiableCredential
            .fromTemplate(template, true, mergedData)

        val id = "${UUID.randomUUID()}"
        val type = ISSUE_CREDENTIAL_MESSAGE_TYPE_PROPOSE_CREDENTIAL

        val proposal = ProposalMetaData.Builder()
            .goalCode(options["goal_code"] as? String)
            .comment(options["comment"] as? String)
            .credentialPreview(subjectData)
            .build()

        val jsonData = Attachment.Data.Json.parse(mapOf("json" to unsignedVc.toMap()))
        val vcAttachment = Attachment.Builder("${UUID.randomUUID()}", jsonData)
            .format(CREDENTIAL_ATTACHMENT_FORMAT)
            .mediaType(JSON_MIME_TYPE)
            .build()

        val vcProposalMsg = MessageBuilder(id, proposal.toMap(), type)
            .thid(id)
            .to(listOf(issuerDid.uri))
            .from(holderDid.uri)
            .attachments(listOf(vcAttachment))
            .build()

        mex.addMessage(EndpointMessage.Builder(vcProposalMsg).outbound().build())
        log.info { "Holder (${holder.name}) proposes credential: ${vcProposalMsg.encodeJson(true)}" }

        mex.placeEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL)

        dispatchEncryptedMessage(pcon, vcProposalMsg) { packedEpm ->
            log.info { "Holder (${holder.name}) sends credential proposal: ${packedEpm.prettyPrint()}" }
        }

        return IssueCredentialProtocolV3(mex)
    }

    /**
     * Offer Credential
     *
     * Supported options
     * -----------------
     * goal_code: String
     * comment: String
     * credential_preview: String
     */
    fun sendCredentialOffer(
        issuer: Wallet,
        holderDid: Did,
        template: String,
        subjectData: Map<String, Any?>,
        options: Map<String, Any> = mapOf()
    ): IssueCredentialProtocolV3 {

        val mex = MessageExchange.findByWallet(issuer.name).firstOrNull { it.getConnection().theirDid == holderDid }
        checkNotNull(mex) { "No message exchange for: ${holderDid.uri}"}
        val pcon = mex.getConnection()
        val issuerDid = pcon.myDid

        val credentialTemplate = """{
            "id": "urn:uuid:${UUID.randomUUID()}",
            "issuer": "${issuerDid.uri}",
            "issuanceDate": "${dateTimeNow()}",
            "credentialSubject": {
                "id": "${holderDid.uri}"
            }
        }""".decodeJson()

        val subjectTemplate = """{
            "credentialSubject": ${subjectData.encodeJson()}
        }""".decodeJson()

        val mergedData = credentialTemplate.unionMap(subjectTemplate)

        val unsignedVc = W3CVerifiableCredential
            .fromTemplate(template, true, mergedData)
            .validate()

        val proofConfig = ProofConfig(
            issuerDid = issuerDid.uri,
            subjectDid = holderDid.uri,
            proofPurpose = "assertionMethod",
            proofType = ProofType.LD_PROOF)

        val signedVc = signatory.issue(unsignedVc, proofConfig, false)
        checkNotNull(signedVc.credentialSubject) { "No credentialSubject" }
        val subjectDataFull = signedVc.credentialSubject.toMap()

        val id = "${UUID.randomUUID()}"
        val type = ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL

        val offerMeta = OfferMetaData.Builder()
            .credentialPreview(subjectDataFull)
            .goalCode(options["goal_code"] as? String)
            .comment(options["comment"] as? String)
            .replacementId(options["replacement_id"] as? String)
            .build()

        val jsonData = Attachment.Data.Json.parse(mapOf("json" to signedVc.toMap()))
        val vcAttachment = Attachment.Builder("${UUID.randomUUID()}", jsonData)
            .format(CREDENTIAL_ATTACHMENT_FORMAT)
            .mediaType(JSON_MIME_TYPE)
            .build()

        val vcOfferMsg = MessageBuilder(id, offerMeta.toMap(), type)
            .thid(id)
            .to(listOf(holderDid.uri))
            .from(issuerDid.uri)
            .attachments(listOf(vcAttachment))
            .build()


        mex.addMessage(EndpointMessage.Builder(vcOfferMsg).outbound().build())
        log.info { "Issuer (${issuer.name}) created credential offer: ${vcOfferMsg.encodeJson(true)}" }

        mex.placeEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL)

        dispatchEncryptedMessage(pcon, vcOfferMsg) { packedEpm ->
            log.info { "Issuer (${issuer.name}) sends credential offer: ${packedEpm.prettyPrint()}" }
        }

        return IssueCredentialProtocolV3(mex)
    }

    fun awaitCredentialOffer(holder: Wallet, issuerDid: Did, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): IssueCredentialProtocolV3 {
        val mex = MessageExchange.findByWallet(holder.name).firstOrNull { it.getConnection().theirDid == issuerDid }
        checkNotNull(mex) { "No message exchange for: ${issuerDid.uri}"}
        mex.awaitEndpointMessage(ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL, timeout, unit)
        return this
    }

    fun awaitCredentialRequest(issuer: Wallet, holderDid: Did, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): IssueCredentialProtocolV3 {
        val mex = MessageExchange.findByWallet(issuer.name).firstOrNull { it.getConnection().theirDid == holderDid }
        checkNotNull(mex) { "No message exchange for: ${holderDid.uri}"}
        mex.awaitEndpointMessage(ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL, timeout, unit)
        return this
    }

    fun awaitIssuedCredential(holder: Wallet, issuerDid: Did, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): IssueCredentialProtocolV3 {
        val mex = MessageExchange.findByWallet(holder.name).firstOrNull { it.getConnection().theirDid == issuerDid }
        checkNotNull(mex) { "No message exchange for: ${issuerDid.uri}"}
        mex.awaitEndpointMessage(ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL, timeout, unit)
        return this
    }

    fun awaitCredentialAck(issuer: Wallet, holderDid: Did, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): IssueCredentialProtocolV3 {
        val mex = MessageExchange.findByWallet(issuer.name).firstOrNull { it.getConnection().theirDid == holderDid }
        checkNotNull(mex) { "No message exchange for: ${holderDid.uri}"}
        mex.awaitEndpointMessage(ISSUE_CREDENTIAL_MESSAGE_TYPE_CREDENTIAL_ACK, timeout, unit)
        return this
    }

    // Private ---------------------------------------------------------------------------------------------------------

    /**
     * Issue credential
     *
     * Supported options
     * -----------------
     * goal_code: String
     * comment: String
     * replacement_id: String
     */
    private fun issueCredential(issuer: Wallet, holderDid: Did, options: Map<String, Any> = mapOf()): IssueCredentialProtocolV3 {

        val pcon = mex.getConnection()
        val issuerDid = pcon.myDid

        val vcRequestMsg = mex.last.body as Message
        mex.checkLastMessageType(ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL)

        val id = "${UUID.randomUUID()}"
        val type = ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL

        val attachmentsFormats = vcRequestMsg.attachments?.map { it.format ?: CREDENTIAL_ATTACHMENT_FORMAT } ?: emptyList()
        check(CREDENTIAL_ATTACHMENT_FORMAT in attachmentsFormats) { "Incompatible attachment formats: $attachmentsFormats" }

        val attachment = vcRequestMsg.attachments?.firstOrNull { at -> at.format == null || at.format == CREDENTIAL_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No credential attachment" }

        val jsonData = gson.toJson(attachment.data.jsonData())
        val vc = W3CVerifiableCredential.fromJson(jsonData)
        issuer.addVerifiableCredential(vc)

        val issuedVcBody: MutableMap<String, Any> = mutableMapOf()
        options["goal_code"]?.also { issuedVcBody["goal_code"] = it }
        options["comment"]?.also { issuedVcBody["comment"] = it }
        options["replacement_id"]?.also { issuedVcBody["replacement_id"] = it }

        val issuedVcMsg = MessageBuilder(id, issuedVcBody, type)
            .thid(vcRequestMsg.id)
            .to(listOf(holderDid.uri))
            .from(issuerDid.uri)
            .attachments(listOf(attachment))
            .build()

        mex.addMessage(EndpointMessage.Builder(issuedVcMsg).outbound().build())
        log.info { "Issuer (${issuer.name}) creates credential: ${issuedVcMsg.encodeJson(true)}" }

        dispatchEncryptedMessage(pcon, issuedVcMsg) { packedEpm ->
            log.info { "Issuer (${issuer.name}) sends credential: ${packedEpm.prettyPrint()}" }
        }
        return this
    }

    private fun receiveCredentialProposal(issuer: Wallet): IssueCredentialProtocolV3 {

        val pcon = mex.getConnection()
        val holderDid = pcon.theirDid

        val vcProposalMsg = mex.last.body as Message
        mex.checkLastMessageType(ISSUE_CREDENTIAL_MESSAGE_TYPE_PROPOSE_CREDENTIAL)

        log.info { "Issuer (${issuer.name}) received credential proposal: ${vcProposalMsg.encodeJson(true)}" }

        // Extract the proposal data from the Message

        val proposalMeta = ProposalMetaData.fromMap(vcProposalMsg.body)

        // Extract the attached credential

        val attachmentsFormats = vcProposalMsg.attachments?.map { it.format ?: CREDENTIAL_ATTACHMENT_FORMAT } ?: emptyList()
        check(CREDENTIAL_ATTACHMENT_FORMAT in attachmentsFormats) { "Incompatible attachment formats: $attachmentsFormats" }

        val attachment = vcProposalMsg.attachments?.firstOrNull { at -> at.format == null || at.format == CREDENTIAL_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No credential proposal attachment" }

        val jsonData = gson.toJson(attachment.data.jsonData())
        val proposedVc = VerifiableCredential.fromJson(jsonData)
        val proposedSchema = proposedVc.credentialSchema
        checkNotNull(proposedSchema) { "No credential schema" }

        // Verify that the proposal data matches the subject data in the attached credential

        val credentialSubject = proposedVc.credentialSubject
        checkNotNull(credentialSubject) { "No credentialSubject" }
        val proposedSubjectData = credentialSubject.properties

        val nonMatchingProposalData = proposalMeta.credentialPreview.filter { (pn, pv, _) ->
            when(pn) {
                "id" -> pv != "${credentialSubject.id}"
                else -> pv != proposedSubjectData[pn]
            }}
        check(nonMatchingProposalData.isEmpty()) { "Non matching data: ${nonMatchingProposalData.encodeJson()}" }

        log.info { "Issuer (${issuer.name}) accepts credential proposal" }

        // Extract the template name from the attached credential

        val templates = listOf(
            "BirthCertificate",
            "MarriageCertificate",
            "Passport",
            "TravelPermission",
            "UniversityTranscript")

        val template = templates.firstOrNull { proposedSchema.id.matches(Regex("(.+)schema/${it}Schema-draft-(.+)")) }
        checkNotNull(template) { "Not a supported schema: ${proposedSchema.id}" }

        // Copy the goal code from the proposal
        // Note, comment not copied
        val options = mutableMapOf<String, Any>()
        proposalMeta.goalCode?.also { options["goal_code"] = it }

        return sendCredentialOffer(issuer, holderDid, template, proposedSubjectData, options)
    }

    private fun receiveCredentialOffer(holder: Wallet): IssueCredentialProtocolV3 {

        val pcon = mex.getConnection()
        val (holderDid, issuerDid) = Pair(pcon.myDid, pcon.theirDid)

        val vcOfferEpm = mex.last
        val vcOfferMsg = mex.last.body as Message
        mex.checkLastMessageType(ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL)

        val offer = OfferMetaData.fromMap(vcOfferMsg.body)

        val attachmentsFormats = vcOfferMsg.attachments?.map { it.format ?: CREDENTIAL_ATTACHMENT_FORMAT } ?: emptyList()
        check(CREDENTIAL_ATTACHMENT_FORMAT in attachmentsFormats) { "Incompatible attachment formats: $attachmentsFormats" }

        val attachment = vcOfferMsg.attachments?.firstOrNull { at -> at.format == null || at.format == CREDENTIAL_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No credential offer attachment" }

        log.info { "Holder (${holder.name}) accepts credential offer: ${vcOfferMsg.encodeJson(true)}" }

        val vcRequestBody: MutableMap<String, Any?> = mutableMapOf()
        offer.goalCode?.also { vcRequestBody["goal_code"] = it }
        offer.comment?.also { vcRequestBody["comment"] = it }

        val id = "${UUID.randomUUID()}"
        val type = ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL

        val vcRequestMsg = MessageBuilder(id, vcRequestBody, type)
            .thid(vcOfferMsg.id)
            .to(listOf(issuerDid.uri))
            .from(holderDid.uri)
            .attachments(listOf(attachment))
            .build()

        mex.addMessage(EndpointMessage.Builder(vcRequestMsg).outbound().build())
        log.info { "Holder (${holder.name}) creates credential requests: ${vcRequestMsg.encodeJson(true)}" }

        mex.placeEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL)

        dispatchEncryptedMessage(pcon, vcRequestMsg) { packedEpm ->
            log.info { "Holder (${holder.name}) sends credential requests: ${packedEpm.prettyPrint()}" }
        }

        if (mex.hasEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL))
            mex.completeEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL, vcOfferEpm)

        return this
    }

    private fun receiveCredentialRequest(issuer: Wallet): IssueCredentialProtocolV3 {

        val pcon = mex.getConnection()
        val holderDid = pcon.theirDid

        val vcRequestMsg = mex.last.body as Message
        mex.checkLastMessageType(ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL)

        log.info { "Issuer (${issuer.name}) received credential request: ${vcRequestMsg.encodeJson(true)}" }

        mex.placeEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_CREDENTIAL_ACK)

        issueCredential(issuer, holderDid)

        mex.completeEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL, mex.last)
        return this
    }

    private fun receiveCredential(holder: Wallet): IssueCredentialProtocolV3 {

        val credentialEpm = mex.last
        val credentialMsg = mex.last.body as Message
        mex.checkLastMessageType(ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL)

        val attachmentsFormats = credentialMsg.attachments?.map { it.format ?: CREDENTIAL_ATTACHMENT_FORMAT } ?: emptyList()
        check(CREDENTIAL_ATTACHMENT_FORMAT in attachmentsFormats) { "Incompatible attachment formats: $attachmentsFormats" }

        val attachment = credentialMsg.attachments?.firstOrNull { at -> at.format == null || at.format == CREDENTIAL_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No credential attachment" }

        val jsonData = gson.toJson(attachment.data.jsonData())
        val vc = W3CVerifiableCredential.fromJson(jsonData)
        holder.addVerifiableCredential(vc)

        log.info { "Holder (${holder.name}) received credential: ${vc.encodeJson(true)}" }

        sendCredentialAck(holder, credentialEpm)

        mex.completeEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL, credentialEpm)
        return this
    }

    private fun receiveCredentialAck(issuer: Wallet): IssueCredentialProtocolV3 {

        val ackMsg = mex.last.body as Message
        mex.checkLastMessageType(ISSUE_CREDENTIAL_MESSAGE_TYPE_CREDENTIAL_ACK)

        log.info { "Issuer (${issuer.name}) received credential ack: ${ackMsg.encodeJson(true)}" }

        mex.completeEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_CREDENTIAL_ACK, mex.last)
        return this
    }

    private fun sendCredentialAck(holder: Wallet, credentialEpm: EndpointMessage): IssueCredentialProtocolV3 {

        val credentialMsg = mex.last.body as Message
        credentialEpm.checkMessageType(ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL)

        val pcon = mex.getConnection()
        val (holderDid, issuerDid) = Pair(pcon.myDid, pcon.theirDid)

        val id = "${UUID.randomUUID()}"
        val type = ISSUE_CREDENTIAL_MESSAGE_TYPE_CREDENTIAL_ACK

        val vcAckMsg = MessageBuilder(id, mapOf(), type)
            .thid(credentialMsg.id)
            .to(listOf(issuerDid.uri))
            .from(holderDid.uri)
            .build()

        mex.addMessage(EndpointMessage.Builder(vcAckMsg).outbound().build())
        log.info { "Holder (${holder.name}) creates credential ack: ${vcAckMsg.encodeJson(true)}" }

        dispatchEncryptedMessage(pcon, vcAckMsg) { packedEpm ->
            log.info { "Holder (${holder.name}) sends credential ack: ${packedEpm.prettyPrint()}" }
        }

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
         * Optional field that provides human readable information about this Credential Proposal, so the offer can be evaluated by human judgment
         */
        @SerializedName("comment")
        val comment: String?,

        /**
         * A JSON-LD object that represents the credential data that the Holder proposes.
         */
        @SerializedName("credential_preview")
        val credentialPreview: List<PreviewAttribute>,
    ) {
        companion object {

            @Suppress("UNCHECKED_CAST")
            fun fromMap(body: Map<String, Any?>): ProposalMetaData {
                val builder = Builder()
                body["goal_code"]?.also { builder.goalCode(it as String) }
                body["comment"]?.also { builder.comment(it as String) }
                body["credential_preview"]?.also { builder.credentialPreview(it as List<Map<String, Any>>) }
                return builder.build()
            }
        }

        fun toMap() = encodeJson().decodeJson()

        class Builder {
            private var goalCode: String? = null
            private var comment: String? = null
            private var credentialPreview: List<PreviewAttribute>? = null

            fun goalCode(goalCode: String?) = apply { this.goalCode = goalCode }
            fun comment(comment: String?) = apply { this.comment = comment }

            fun credentialPreview(entries: Map<String, Any>) = apply {
                credentialPreview = entries.map { (k, v) -> PreviewAttribute(k, v) }
            }
            fun credentialPreview(entries: List<Map<String, Any>>) = apply {
                credentialPreview = entries.map { el -> PreviewAttribute.fromJson(el.encodeJson()) }
            }

            fun build(): ProposalMetaData {
                checkNotNull(credentialPreview) { "No credentialPreview" }
                return ProposalMetaData(goalCode, comment, credentialPreview!!)
            }
        }
    }

    data class OfferMetaData(

        /**
         * Optional field that indicates the goal of the message sender
         */
        @SerializedName("goal_code")
        val goalCode: String?,

        /**
         * Optional field that provides human readable information about this Credential Offer, so the offer can be evaluated by human judgment
         */
        @SerializedName("comment")
        val comment: String?,

        /**
         * An optional field to help coordinate credential replacement. When this is present and matches the replacement_id of a previously issued credential,
         * it may be used to inform the recipient that the offered credential is considered to be a replacement to the previous credential.
         * This value is unique to the issuer. It must not be used in a credential presentation.
         */
        @SerializedName("replacement_id")
        val replacementId: String?,

        /**
         * A JSON-LD object that represents the credential data that the Issuer is willing to issue
         */
        @SerializedName("credential_preview")
        val credentialPreview: List<PreviewAttribute>
    ) {
        companion object {

            @Suppress("UNCHECKED_CAST")
            fun fromMap(body: Map<String, Any?>): OfferMetaData {
                val builder = Builder()
                body["goal_code"]?.also { builder.goalCode(it as String) }
                body["comment"]?.also { builder.comment(it as String) }
                body["replacement_id"]?.also { builder.replacementId(it as String) }
                body["credential_preview"]?.also { builder.credentialPreview(it as List<Map<String, Any>>) }
                return builder.build()
            }
        }

        fun toMap() = encodeJson().decodeJson()

        class Builder {
            private var goalCode: String? = null
            private var comment: String? = null
            private var replacementId: String? = null
            private var credentialPreview: List<PreviewAttribute>? = null

            fun goalCode(goalCode: String?) = apply { this.goalCode = goalCode }
            fun comment(comment: String?) = apply { this.comment = comment }
            fun replacementId(replacementId: String?) = apply { this.replacementId = replacementId }

            fun credentialPreview(entries: Map<String, Any?>) = apply {
                credentialPreview = entries.map { (k, v) -> PreviewAttribute(k, v ?: "") }
            }
            fun credentialPreview(entries: List<Map<String, Any>>) = apply {
                credentialPreview = entries.map { el -> PreviewAttribute.fromJson(el.encodeJson()) }
            }

            fun build(): OfferMetaData {
                checkNotNull(credentialPreview) { "No credentialPreview" }
                return OfferMetaData(goalCode, comment, replacementId, credentialPreview!!)
            }
        }
    }
}
