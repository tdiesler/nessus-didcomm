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
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
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
import org.nessus.didcomm.service.ISSUE_CREDENTIAL_PROTOCOL_V3
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.jsonData
import org.nessus.didcomm.util.unionMap
import java.util.UUID
import java.util.concurrent.TimeUnit


/**
 * WACI DIDCommS: Issue Credential Protocol 3.0
 * https://github.com/decentralized-identity/waci-didcomm/tree/main/issue_credential
 */
class IssueCredentialV3Protocol(mex: MessageExchange): Protocol<IssueCredentialV3Protocol>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = ISSUE_CREDENTIAL_PROTOCOL_V3.uri

    companion object {
        val ISSUE_CREDENTIAL_MESSAGE_TYPE_PROPOSE_CREDENTIAL = "${ISSUE_CREDENTIAL_PROTOCOL_V3.uri}/propose-credential"
        val ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL = "${ISSUE_CREDENTIAL_PROTOCOL_V3.uri}/offer-credential"
        val ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL = "${ISSUE_CREDENTIAL_PROTOCOL_V3.uri}/request-credential"
        val ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL = "${ISSUE_CREDENTIAL_PROTOCOL_V3.uri}/issue-credential"

        const val CREDENTIAL_ATTACHMENT_FORMAT = "https://www.w3.org/TR/vc-data-model/"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.NESSUS)

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            ISSUE_CREDENTIAL_MESSAGE_TYPE_PROPOSE_CREDENTIAL -> receiveCredentialProposal(to)
            ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL -> receiveCredentialOffer(to)
            ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL -> receiveCredentialRequest(to)
            ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL -> receiveIssuedCredential(to)
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
    ): IssueCredentialV3Protocol {

        val mex = MessageExchange.findByWallet(holder.name)
            .first { it.getConnection().theirDid == issuerDid }

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
            .fromTemplate(template, mergedData)

        val id = "${UUID.randomUUID()}"
        val type = ISSUE_CREDENTIAL_MESSAGE_TYPE_PROPOSE_CREDENTIAL

        val proposal = CredentialProposal.Builder()
            .goalCode(options["goal_code"] as? String)
            .comment(options["comment"] as? String)
            .credentialPreview(subjectData)
            .build()

        val jsonData = Attachment.Data.Json.parse(mapOf("json" to unsignedVc.jsonObject))
        val vcAttachment = Attachment.Builder("${UUID.randomUUID()}", jsonData)
            .format(CREDENTIAL_ATTACHMENT_FORMAT)
            .mediaType("application/json")
            .build()

        val proposalMsg = MessageBuilder(id, proposal.toMap(), type)
            .thid(id)
            .to(listOf(issuerDid.uri))
            .from(holderDid.uri)
            .attachments(listOf(vcAttachment))
            .build()

        log.info { "Holder (${holder.name}) proposes credential: ${proposalMsg.encodeJson(true)}" }

        val epm = EndpointMessage.Builder(proposalMsg).outbound().build()
        mex.addMessage(epm)

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(proposalMsg, issuerDid.uri)
                .signFrom(holderDid.uri)
                .from(holderDid.uri)
                .build()
        )

        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage.Builder(packedMessage, mapOf(
                MESSAGE_HEADER_ID to "${proposalMsg.id}.packed",
                MESSAGE_HEADER_TYPE to Typ.Encrypted.typ))
            .outbound().build()
        log.info { "Holder (${holder.name}) sends credential proposal: ${proposalMsg.encodeJson(true)}" }

        mex.placeEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL)
        mex.placeEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL)

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
        return IssueCredentialV3Protocol(mex)
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
        subjectData: Map<String, Any>,
        options: Map<String, Any> = mapOf()
    ): IssueCredentialV3Protocol {

        val mex = MessageExchange.findByWallet(issuer.name)
            .first { it.getConnection().theirDid == holderDid }

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
            .fromTemplate(template, mergedData)
            .validate()

        val proofConfig = ProofConfig(
            issuerDid = issuerDid.uri,
            subjectDid = holderDid.uri,
            proofPurpose = "assertionMethod",
            proofType = ProofType.LD_PROOF)

        val signedVc = signatory.issue(unsignedVc, proofConfig, false)
        val subjectDataFull = signedVc.credentialSubject.jsonObject

        val id = "${UUID.randomUUID()}"
        val type = ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL

        val offer = CredentialOffer.Builder()
            .credentialPreview(subjectDataFull)
            .goalCode(options["goal_code"] as? String)
            .comment(options["comment"] as? String)
            .replacementId(options["replacement_id"] as? String)
            .build()

        val jsonData = Attachment.Data.Json.parse(mapOf("json" to signedVc.jsonObject))
        val vcAttachment = Attachment.Builder("${UUID.randomUUID()}", jsonData)
            .format(CREDENTIAL_ATTACHMENT_FORMAT)
            .mediaType("application/json")
            .build()

        val offerCredentialMsg = MessageBuilder(id, offer.toMap(), type)
            .thid(id)
            .to(listOf(holderDid.uri))
            .from(issuerDid.uri)
            .attachments(listOf(vcAttachment))
            .build()

        log.info { "Issuer (${issuer.name}) created credential offer: ${offerCredentialMsg.encodeJson(true)}" }

        val epm = EndpointMessage.Builder(offerCredentialMsg).outbound().build()
        mex.addMessage(epm)

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(offerCredentialMsg, holderDid.uri)
                .signFrom(issuerDid.uri)
                .from(issuerDid.uri)
                .build()
        )

        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage.Builder(packedMessage, mapOf(
                MESSAGE_HEADER_ID to "${offerCredentialMsg.id}.packed",
                MESSAGE_HEADER_TYPE to Typ.Encrypted.typ))
            .outbound()
            .build()
        log.info { "Issuer (${issuer.name}) sends credential offer: ${packedEpm.prettyPrint()}" }

        mex.placeEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL)

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
        return IssueCredentialV3Protocol(mex)
    }

    fun awaitCredentialOffer(holder: Wallet, issuerDid: Did, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): IssueCredentialV3Protocol {
        val mex = MessageExchange.findByWallet(holder.name).first { it.getConnection().theirDid == issuerDid }
        mex.awaitEndpointMessage(ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL, timeout, unit)
        return this
    }

    fun awaitCredentialRequest(issuer: Wallet, holderDid: Did, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): IssueCredentialV3Protocol {
        val mex = MessageExchange.findByWallet(issuer.name).first { it.getConnection().theirDid == holderDid }
        mex.awaitEndpointMessage(ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL, timeout, unit)
        return this
    }

    /**
     * Issue credential
     *
     * Supported options
     * -----------------
     * goal_code: String
     * comment: String
     * replacement_id: String
     */
    fun issueCredential(issuer: Wallet, holderDid: Did, options: Map<String, Any> = mapOf()): IssueCredentialV3Protocol {

        val mex = MessageExchange.findByWallet(issuer.name)
            .first { it.getConnection().theirDid == holderDid }

        val pcon = mex.getConnection()
        val issuerDid = pcon.myDid

        val requestCredentialEpm = mex.last
        val requestCredentialMsg = mex.last.body as Message
        requestCredentialEpm.checkMessageType(ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL)

        val id = "${UUID.randomUUID()}"
        val type = ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL

        val attachment = requestCredentialMsg.attachments?.firstOrNull { at -> at.format == null || at.format == CREDENTIAL_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No credential attachment" }

        val issueCredentialBody: MutableMap<String, Any> = mutableMapOf()
        options["goal_code"]?.also { issueCredentialBody["goal_code"] = it }
        options["comment"]?.also { issueCredentialBody["comment"] = it }
        options["replacement_id"]?.also { issueCredentialBody["replacement_id"] = it }

        val issueCredentialMsg = MessageBuilder(id, issueCredentialBody, type)
            .thid(requestCredentialMsg.id)
            .to(listOf(holderDid.uri))
            .from(issuerDid.uri)
            .attachments(listOf(attachment))
            .build()

        log.info { "Issuer (${issuer.name}) issues credential: ${issueCredentialMsg.encodeJson(true)}" }

        val epm = EndpointMessage.Builder(issueCredentialMsg).outbound().build()
        mex.addMessage(epm)

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(issueCredentialMsg, holderDid.uri)
                .signFrom(issuerDid.uri)
                .from(issuerDid.uri)
                .build()
        )

        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage.Builder(packedMessage, mapOf(
                MESSAGE_HEADER_ID to "${issueCredentialMsg.id}.packed",
                MESSAGE_HEADER_TYPE to Typ.Encrypted.typ))
            .outbound()
            .build()
        log.info { "Issuer (${issuer.name}) sends credential: ${packedEpm.prettyPrint()}" }

        val holderMex = MessageExchange.findByVerkey(holderDid.verkey)
        holderMex?.placeEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL)

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
        return this
    }

    fun awaitIssuedCredential(holder: Wallet, issuerDid: Did, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): IssueCredentialV3Protocol {
        val mex = MessageExchange.findByWallet(holder.name).first { it.getConnection().theirDid == issuerDid }
        mex.awaitEndpointMessage(ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL, timeout, unit)
        return this
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun receiveCredentialProposal(issuer: Wallet): IssueCredentialV3Protocol {

        val pcon = mex.getConnection()
        val holderDid = pcon.theirDid

        val credentialProposalEpm = mex.last
        val credentialProposalMsg = mex.last.body as Message
        credentialProposalEpm.checkMessageType(ISSUE_CREDENTIAL_MESSAGE_TYPE_PROPOSE_CREDENTIAL)

        log.info { "Issuer (${issuer.name}) received credential proposal: ${credentialProposalMsg.encodeJson(true)}" }

        // Extract the proposal data from the Message

        val proposal = CredentialProposal.fromMap(credentialProposalMsg.body)

        // Extract the attached credential

        val attachmentsFormats = credentialProposalMsg.attachments?.map { it.format } ?: listOf(CREDENTIAL_ATTACHMENT_FORMAT)
        check(CREDENTIAL_ATTACHMENT_FORMAT in attachmentsFormats) { "Incompatible attachment formats: $attachmentsFormats" }

        val attachment = credentialProposalMsg.attachments?.firstOrNull { at -> at.format == null || at.format == CREDENTIAL_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No credential proposal attachment" }

        val attachmentData = attachment.data.jsonData()
        checkNotNull(attachmentData) { "No attachment data" }

        val proposedVc = W3CVerifiableCredential.fromJson(attachmentData)
        val proposedSubjectData = proposedVc.credentialSubject.claims
        val proposedSchema = proposedVc.credentialSchema
        checkNotNull(proposedSchema) { "No credential schema" }

        // Verify that the proposal data matches the subject data in the attached credential

        val nonMatchingProposalData = proposal.credentialPreview.filter { (pn, pv, _) -> pv != proposedSubjectData[pn] }
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
        proposal.goalCode?.also { options["goal_code"] = it }

        return sendCredentialOffer(issuer, holderDid, template, proposedSubjectData, options)
    }

    private fun receiveCredentialOffer(holder: Wallet): IssueCredentialV3Protocol {

        val pcon = mex.getConnection()
        val (holderDid, issuerDid) = Pair(pcon.myDid, pcon.theirDid)

        val credentialOfferEpm = mex.last
        val credentialOfferMsg = mex.last.body as Message
        credentialOfferEpm.checkMessageType(ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL)

        val offer = CredentialOffer.fromMap(credentialOfferMsg.body)
        
        val attachmentsFormats = credentialOfferMsg.attachments?.map { it.format } ?: listOf(CREDENTIAL_ATTACHMENT_FORMAT)
        check(CREDENTIAL_ATTACHMENT_FORMAT in attachmentsFormats) { "Incompatible attachment formats: $attachmentsFormats" }

        val attachment = credentialOfferMsg.attachments?.firstOrNull { at -> at.format == null || at.format == CREDENTIAL_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No credential offer attachment" }

        log.info { "Holder (${holder.name}) accepts credential offer: ${credentialOfferMsg.encodeJson(true)}" }

        if (mex.hasEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL))
            mex.completeEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL, credentialOfferEpm)

        val credentialRequestBody: MutableMap<String, Any?> = mutableMapOf()
        offer.goalCode?.also { credentialRequestBody["goal_code"] = it }
        offer.comment?.also { credentialRequestBody["comment"] = it }

        val id = "${UUID.randomUUID()}"
        val type = ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL

        val credentialRequestMsg = MessageBuilder(id, credentialRequestBody, type)
            .thid(credentialOfferMsg.id)
            .to(listOf(issuerDid.uri))
            .from(holderDid.uri)
            .attachments(listOf(attachment))
            .build()

        log.info { "Holder (${holder.name}) creates credential requests: ${credentialRequestMsg.encodeJson(true)}" }

        val epm = EndpointMessage.Builder(credentialRequestMsg).outbound().build()
        mex.addMessage(epm)

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(credentialRequestMsg, issuerDid.uri)
                .signFrom(holderDid.uri)
                .from(holderDid.uri)
                .build()
        )

        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage.Builder(packedMessage, mapOf(
                MESSAGE_HEADER_ID to "${credentialRequestMsg.id}.packed",
                MESSAGE_HEADER_TYPE to Typ.Encrypted.typ))
            .outbound()
            .build()

        log.info { "Holder (${holder.name}) sends credential requests: ${packedEpm.prettyPrint()}" }

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
        return this
    }

    private fun receiveCredentialRequest(issuer: Wallet): IssueCredentialV3Protocol {

        val credentialRequestEpm = mex.last
        val credentialRequestMsg = mex.last.body as Message
        credentialRequestEpm.checkMessageType(ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL)

        log.info { "Issuer (${issuer.name}) received credential request: ${credentialRequestMsg.encodeJson(true)}" }

        mex.completeEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL, mex.last)

        val pcon = mex.getConnection()
        val holderDid = pcon.theirDid

        return issueCredential(issuer, holderDid)
    }

    private fun receiveIssuedCredential(holder: Wallet): IssueCredentialV3Protocol {

        val issuedCredentialEpm = mex.last
        val issuedCredentialMsg = mex.last.body as Message
        issuedCredentialEpm.checkMessageType(ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL)

        val attachment = issuedCredentialMsg.attachments?.firstOrNull { at -> at.format == null || at.format == CREDENTIAL_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No credential attachment" }

        val vcJson = gson.toJson(attachment.data.jsonData())
        val vc = W3CVerifiableCredential.fromJson(vcJson)
        holder.addVerifiableCredential(vc)

        log.info { "Holder (${holder.name}) received credential: ${vc.encodeJson(true)}" }

        mex.completeEndpointMessageFuture(ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL, mex.last)
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

    data class CredentialProposal(

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
            fun fromMap(body: Map<String, Any?>): CredentialProposal {
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

            fun build(): CredentialProposal {
                checkNotNull(credentialPreview) { "No credentialPreview" }
                return CredentialProposal(goalCode, comment, credentialPreview!!)
            }
        }
    }

    data class CredentialOffer(

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
            fun fromMap(body: Map<String, Any?>): CredentialOffer {
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

            fun credentialPreview(entries: Map<String, Any>) = apply {
                credentialPreview = entries.map { (k, v) -> PreviewAttribute(k, v) }
            }
            fun credentialPreview(entries: List<Map<String, Any>>) = apply {
                credentialPreview = entries.map { el -> PreviewAttribute.fromJson(el.encodeJson()) }
            }

            fun build(): CredentialOffer {
                checkNotNull(credentialPreview) { "No credentialPreview" }
                return CredentialOffer(goalCode, comment, replacementId, credentialPreview!!)
            }
        }
    }
}
