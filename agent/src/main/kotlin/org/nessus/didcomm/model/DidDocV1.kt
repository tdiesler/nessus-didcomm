package org.nessus.didcomm.model

import id.walt.common.KlaxonWithConverters
import id.walt.crypto.LdVerificationKeyType.Ed25519VerificationKey2018
import id.walt.crypto.LdVerificationKeyType.Ed25519VerificationKey2019
import id.walt.crypto.LdVerificationKeyType.Ed25519VerificationKey2020
import id.walt.crypto.LdVerificationKeyType.JwsVerificationKey2020
import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.diddoc.DIDCommService
import org.didcommx.didcomm.diddoc.DIDDocDecoder
import org.didcommx.didcomm.diddoc.DIDDocEncoder
import org.didcommx.didcomm.diddoc.VerificationMethod
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.jsonData
import java.util.UUID

typealias SicpaDidDoc = org.didcommx.didcomm.diddoc.DIDDoc
typealias WaltIdVerificationMethod = id.walt.model.VerificationMethod

val DEFAULT_ACCEPT = listOf("didcomm/v2") //, "didcomm/aip2;env=rfc587")

data class DidDocV1(
    val id: String,
    val context: List<String>,
    val alsoKnownAs: List<String>,
    val controller: List<String>,
    val authentications: List<String>,
    val assertionMethods: List<String>,
    val keyAgreements: List<String>,
    val capabilityInvocations: List<String>,
    val capabilityDelegations: List<String>,
    val verificationMethods: List<VerificationMethod>,
    val didCommServices: List<DIDCommService>
) {
    companion object {

        fun fromSicpaDidDoc(doc: SicpaDidDoc) = DidDocV1(
            doc.did,
            context = doc.context,
            alsoKnownAs = doc.alsoKnownAs,
            controller = doc.controller,
            authentications = doc.authentications,
            assertionMethods = doc.assertionMethods,
            keyAgreements = doc.keyAgreements,
            capabilityInvocations = doc.capabilityInvocations,
            capabilityDelegations = doc.capabilityDelegations,
            verificationMethods = doc.verificationMethods,
            didCommServices = doc.didCommServices
        )

        fun fromMessage(message: Message): DidDocV1? {
            return message.attachments
                ?.firstOrNull { it.mediaType == DID_DOCUMENT_MEDIA_TYPE }
                ?.let { fromAttachment(it) }
        }

        fun fromAttachment(attachment: Attachment): DidDocV1 {
            require(attachment.mediaType == DID_DOCUMENT_MEDIA_TYPE) { "Unexpected media_type: ${attachment.mediaType} "}
            val didDocAttachment = gson.toJson(attachment.data.jsonData())
            checkNotNull(didDocAttachment) {"Cannot find attached did document"}
            return fromSicpaDidDoc(DIDDocDecoder.decodeJson(didDocAttachment))
        }
    }

    val serviceEndpoint: String?
        get() = didCommServices.map { it.serviceEndpoint }.firstOrNull()

    fun encodeJson(pretty: Boolean = false): String {
        return DIDDocEncoder.encodeJson(toSicpaDidDoc(), pretty)
    }

    fun findVerificationMethod(predicate: (vm: VerificationMethod) -> Boolean): VerificationMethod? {
        return verificationMethods.firstOrNull { predicate.invoke(it) }
    }

    fun toAttachment(): Attachment {
        val didDocMap = encodeJson().decodeJson()
        val jsonData = Attachment.Data.Json.parse(mapOf("json" to didDocMap))
        return Attachment.Builder("${UUID.randomUUID()}", jsonData)
            .mediaType(DID_DOCUMENT_MEDIA_TYPE)
            .build()
    }

    internal fun toSicpaDidDoc(): SicpaDidDoc {
        return SicpaDidDoc(id, context, alsoKnownAs, controller, authentications, assertionMethods, keyAgreements, capabilityInvocations, capabilityDelegations, verificationMethods, didCommServices)
    }

    override fun toString(): String {
        return encodeJson()
    }
}

@Suppress("DEPRECATION")
fun WaltIdVerificationMethod.toVerificationMethod() = VerificationMethod(
    id = id,
    type = when(type) {
        // [TODO] Sicpa does not have ED25519_VERIFICATION_KEY_2019. Is that a problem?
        Ed25519VerificationKey2018.name,
        Ed25519VerificationKey2019.name -> VerificationMethodType.ED25519_VERIFICATION_KEY_2018
        Ed25519VerificationKey2020.name -> VerificationMethodType.ED25519_VERIFICATION_KEY_2020
        // There is no constant in WaltId for this
        "X25519KeyAgreementKey2019" -> VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019
        "X25519KeyAgreementKey2020" -> VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020
        JwsVerificationKey2020.name -> VerificationMethodType.JSON_WEB_KEY_2020
        else -> throw IllegalArgumentException("Unsupported type: $type")
    },
    verificationMaterial = when {
        publicKeyJwk != null -> VerificationMaterial(
            format = VerificationMaterialFormat.JWK,
            value = KlaxonWithConverters().toJsonString(publicKeyJwk)

        )
        publicKeyBase58 != null -> VerificationMaterial(
            format = VerificationMaterialFormat.BASE58,
            value = publicKeyBase58 as String

        )
        publicKeyMultibase != null -> VerificationMaterial(
            format = VerificationMaterialFormat.MULTIBASE,
            value = publicKeyMultibase as String

        )
        publicKeyPem != null -> VerificationMaterial(
            format = VerificationMaterialFormat.OTHER,
            value = publicKeyPem as String

        )
        ethereumAddress != null -> VerificationMaterial(
            format = VerificationMaterialFormat.OTHER,
            value = ethereumAddress as String

        )
        else -> throw IllegalArgumentException("Unsupported verification material: ${KlaxonWithConverters().toJsonString(this)}")
    },
    controller = controller
)