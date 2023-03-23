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
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.RFC0453_ISSUE_CREDENTIAL_V3
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.unionMap
import org.nessus.didcomm.w3c.W3CVerifiableCredential
import java.util.UUID
import java.util.concurrent.TimeUnit


/**
 * WACI DIDComm RFC0453: Issue Credential Protocol 3.0
 * https://github.com/decentralized-identity/waci-didcomm/tree/main/issue_credential
 */
class RFC0453IssueCredentialV3(mex: MessageExchange): Protocol<RFC0453IssueCredentialV3>(mex) {
    override val log = KotlinLogging.logger {}

    override val protocolUri = RFC0453_ISSUE_CREDENTIAL_V3.uri

    companion object {
        val RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL = "${RFC0453_ISSUE_CREDENTIAL_V3.uri}/offer-credential"
        val RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL = "${RFC0453_ISSUE_CREDENTIAL_V3.uri}/request-credential"
        val RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL = "${RFC0453_ISSUE_CREDENTIAL_V3.uri}/issue-credential"
        val CREDENTIAL_ATTACHMENT_FORMAT = "https://www.w3.org/TR/vc-data-model/"
    }

    override val supportedAgentTypes
        get() = listOf(AgentType.NESSUS)

    override fun invokeMethod(to: Wallet, messageType: String): Boolean {
        when (messageType) {
            RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL -> receiveCredentialOffer(to)
            RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL -> receiveCredentialRequest(to)
            RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL -> receiveIssuedCredential(to)
            else -> throw IllegalStateException("Unsupported message type: $messageType")
        }
        return true
    }

    /**
     * Offer Credential
     *
     * Supported options
     * -----------------
     * goal_code: String
     * comment: String
     * replacement_id: String
     */
    fun sendCredentialOffer(issuer: Wallet, holder: Wallet, template: String, subjectData: Map<String, Any>, options: Map<String, Any> = mapOf()): RFC0453IssueCredentialV3 {

        val mex = MessageExchange.findByWallet(issuer)
        val pcon = mex.getConnection()

        check(pcon.myWallet == issuer) { "Issuer not connected through: ${pcon.shortString()}" }
        check(pcon.theirWallet == holder) { "Holder not connected through: ${pcon.shortString()}" }

        val (issuerDid, holderDid) = Pair(pcon.myDid, pcon.theirDid)

        checkAgentType(issuer.agentType)
        checkAgentType(holder.agentType)

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

        val id = "${UUID.randomUUID()}"
        val type = RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL

        val credentialOffer = CredentialOffer.Builder()
            .credentialPreview(signedVc)
            .goalCode(options["goal_code"] as? String)
            .comment(options["comment"] as? String)
            .replacementId(options["replacement_id"] as? String)
            .build()

        val jsonData = Attachment.Data.Json.parse(mapOf("json" to signedVc.jsonObject))
        val vcAttachment = Attachment.Builder("${UUID.randomUUID()}", jsonData)
            .format(CREDENTIAL_ATTACHMENT_FORMAT)
            .mediaType("application/json")
            .build()

        val offerCredentialMsg = MessageBuilder(id, credentialOffer.toMap(), type)
            .thid(id)
            .to(listOf(holderDid.uri))
            .from(issuerDid.uri)
            .attachments(listOf(vcAttachment))
            .build()

        log.info { "Issuer (${issuer.name}) created credential offer: ${offerCredentialMsg.prettyPrint()}" }

        val epm = EndpointMessage(offerCredentialMsg)
        mex.addMessage(epm)

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(offerCredentialMsg, holderDid.uri)
                .signFrom(issuerDid.uri)
                .from(issuerDid.uri)
                .build()
        )

        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage(packedMessage, mapOf(
            EndpointMessage.MESSAGE_HEADER_ID to "${offerCredentialMsg.id}.packed",
            EndpointMessage.MESSAGE_HEADER_TYPE to Typ.Encrypted.typ,
        ))
        log.info { "Issuer (${issuer.name}) sends credential offer: ${packedEpm.prettyPrint()}" }

        mex.placeEndpointMessageFuture(RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL)

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
        return RFC0453IssueCredentialV3(mex)
    }

    fun awaitCredentialRequest(issuer: Wallet, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): RFC0453IssueCredentialV3 {
        val mex = MessageExchange.findByWallet(issuer); val pcon = mex.getConnection()
        check(issuer == pcon.myWallet) { "Issuer not connected through: ${pcon.shortString()}" }
        mex.awaitEndpointMessage(RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL, timeout, unit)
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
    fun issueCredential(issuer: Wallet? = null, options: Map<String, Any> = mapOf()): RFC0453IssueCredentialV3 {

        val pcon = mex.getConnection()
        check(issuer == null || issuer == pcon.myWallet) { "Issuer not connected through: ${pcon.shortString()}" }

        val (issuerDid, holderDid) = Pair(pcon.myDid, pcon.theirDid)
        val holder = pcon.theirWallet as Wallet

        val requestCredentialEpm = mex.last
        val requestCredentialMsg = mex.last.body as Message
        requestCredentialEpm.checkMessageType(RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL)

        val id = "${UUID.randomUUID()}"
        val type = RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL

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

        log.info { "Issuer (${issuer?.name}) issues credential: ${issueCredentialMsg.prettyPrint()}" }

        val epm = EndpointMessage(issueCredentialMsg)
        mex.addMessage(epm)

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(issueCredentialMsg, holderDid.uri)
                .signFrom(issuerDid.uri)
                .from(issuerDid.uri)
                .build()
        )

        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage(packedMessage, mapOf(
            EndpointMessage.MESSAGE_HEADER_ID to "${issueCredentialMsg.id}.packed",
            EndpointMessage.MESSAGE_HEADER_TYPE to Typ.Encrypted.typ,
        ))
        log.info { "Issuer (${issuer?.name}) sends credential: ${packedEpm.prettyPrint()}" }

        val holderMex = MessageExchange.findByWallet(holder)
        holderMex.placeEndpointMessageFuture(RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL)

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
        return this
    }

    fun awaitIssuedCredential(holder: Wallet, timeout: Int = 10, unit: TimeUnit = TimeUnit.SECONDS): RFC0453IssueCredentialV3 {
        val mex = MessageExchange.findByWallet(holder); val pcon = mex.getConnection()
        check(holder == pcon.myWallet) { "Holder not connected through: ${pcon.shortString()}" }
        mex.awaitEndpointMessage(RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL, timeout, unit)
        return this
    }

    // Private ---------------------------------------------------------------------------------------------------------

    /**
     * Receive credential offer
     *
     * Supported options
     * -----------------
     * goal_code: String
     * comment: String
     */
    private fun receiveCredentialOffer(holder: Wallet, options: Map<String, Any> = mapOf()): RFC0453IssueCredentialV3 {

        val pcon = mex.getConnection()
        val (holderDid, issuerDid) = Pair(pcon.myDid, pcon.theirDid)

        val credentialOfferEpm = mex.last
        val credentialOfferMsg = mex.last.body as Message
        credentialOfferEpm.checkMessageType(RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_OFFER_CREDENTIAL)

        val attachmentsFormats = credentialOfferMsg.attachments?.map { it.format } ?: listOf(CREDENTIAL_ATTACHMENT_FORMAT)
        check(CREDENTIAL_ATTACHMENT_FORMAT in attachmentsFormats) { "Incompatible attachment formats: $attachmentsFormats" }

        val attachment = credentialOfferMsg.attachments?.firstOrNull { at -> at.format == null || at.format == CREDENTIAL_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No credential offer attachment" }

        log.info { "Holder (${holder.name}) accepts credential offer: ${credentialOfferMsg.prettyPrint()}" }

        val credentialRequestBody: MutableMap<String, Any> = mutableMapOf()
        options["goal_code"]?.also { credentialRequestBody["goal_code"] = it }
        options["comment"]?.also { credentialRequestBody["comment"] = it }

        val id = "${UUID.randomUUID()}"
        val type = RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL

        val credentialRequestMsg = MessageBuilder(id, credentialRequestBody, type)
            .thid(credentialOfferMsg.id)
            .to(listOf(issuerDid.uri))
            .from(holderDid.uri)
            .attachments(listOf(attachment))
            .build()

        log.info { "Holder (${holder.name}) creates credential requests: ${credentialRequestMsg.prettyPrint()}" }

        val epm = EndpointMessage(credentialRequestMsg)
        mex.addMessage(epm)

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(credentialRequestMsg, issuerDid.uri)
                .signFrom(holderDid.uri)
                .from(holderDid.uri)
                .build()
        )

        val packedMessage = packResult.packedMessage
        val packedEpm = EndpointMessage(packedMessage, mapOf(
            EndpointMessage.MESSAGE_HEADER_ID to "${credentialRequestMsg.id}.packed",
            EndpointMessage.MESSAGE_HEADER_TYPE to Typ.Encrypted.typ,
        ))

        log.info { "Holder (${holder.name}) sends credential requests: ${packedEpm.prettyPrint()}" }

        dispatchToEndpoint(pcon.theirEndpointUrl, packedEpm)
        return this
    }

    private fun receiveCredentialRequest(issuer: Wallet): RFC0453IssueCredentialV3 {

        val pcon = mex.getConnection()
        val (issuerDid, holderDid) = Pair(pcon.myDid, pcon.theirDid)

        val credentialRequestEpm = mex.last
        val credentialRequestMsg = mex.last.body as Message
        credentialRequestEpm.checkMessageType(RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL)

        log.info { "Issuer (${issuer.name}) received credential request: ${credentialRequestEpm.prettyPrint()}" }

        mex.completeEndpointMessageFuture(RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_REQUEST_CREDENTIAL, mex.last)
        return this
    }

    private fun receiveIssuedCredential(holder: Wallet): RFC0453IssueCredentialV3 {

        val pcon = mex.getConnection()
        val (holderDid, issuerDid) = Pair(pcon.myDid, pcon.theirDid)

        val issuedCredentialEpm = mex.last
        val issuedCredentialMsg = mex.last.body as Message
        issuedCredentialEpm.checkMessageType(RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL)

        val attachment = issuedCredentialMsg.attachments?.firstOrNull { at -> at.format == null || at.format == CREDENTIAL_ATTACHMENT_FORMAT }
        checkNotNull(attachment) { "No credential attachment" }

        val vcJson = gson.toJson(attachment.data.toJSONObject()["json"])
        val vc = W3CVerifiableCredential.fromJson(vcJson)
        holder.addVerifiableCredential(vc)

        log.info { "Holder (${holder.name}) received credential: ${vc.encodeJson(true)}" }

        mex.completeEndpointMessageFuture(RFC0453_ISSUE_CREDENTIAL_MESSAGE_TYPE_ISSUED_CREDENTIAL, mex.last)
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
        val value: String,

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

    data class CredentialOffer(

        /**
         * A JSON-LD object that represents the credential data that Issuer is willing to issue.
         */
        @SerializedName("credential_preview")
        val credentialPreview: List<PreviewAttribute>,

        /**
         * Optional field that indicates the goal of the message sender
         */
        @SerializedName("goal_code")
        val goalCode: String? = null,

        /**
         * Optional field that provides human readable information about this Credential Offer, so the offer can be evaluated by human judgment
         */
        @SerializedName("comment")
        val comment: String? = null,

        /**
         * An optional field to help coordinate credential replacement. When this is present and matches the replacement_id of a previously issued credential,
         * it may be used to inform the recipient that the offered credential is considered to be a replacement to the previous credential.
         * This value is unique to the issuer. It must not be used in a credential presentation.
         */
        @SerializedName("replacement_id")
        val replacementId: String? = null
    ) {
        companion object {

            @Suppress("UNCHECKED_CAST")
            fun fromMap(body: Map<String, Any?>): CredentialOffer {
                val builder = Builder()
                body["credential_preview"]?.also { builder.credentialPreview(it as List<Any>) }
                body["goal_code"]?.also { builder.goalCode(it as String) }
                body["comment"]?.also { builder.comment(it as String) }
                body["replacement_id"]?.also { builder.replacementId(it as String) }
                return builder.build()
            }
        }

        fun toMap() = encodeJson().decodeJson()

        class Builder {
            private var credentialPreview: List<PreviewAttribute>? = null
            private var goalCode: String? = null
            private var comment: String? = null
            private var replacementId: String? = null

            fun credentialPreview(vc: W3CVerifiableCredential) = apply {
                credentialPreview = vc.credentialSubject.jsonObject.map { (k, v) -> PreviewAttribute(k, v.toString()) }
            }
            fun credentialPreview(entries: List<Any>) = apply {
                credentialPreview = entries.map { el -> PreviewAttribute.fromJson(el.encodeJson()) }
            }

            fun goalCode(goalCode: String?) = apply { this.goalCode = goalCode }
            fun comment(comment: String?) = apply { this.comment = comment }
            fun replacementId(replacementId: String?) = apply { this.replacementId = replacementId }

            fun build(): CredentialOffer {
                checkNotNull(credentialPreview) { "No credentialPreview" }
                return CredentialOffer(credentialPreview!!, goalCode, comment, replacementId)
            }
        }
    }
}
