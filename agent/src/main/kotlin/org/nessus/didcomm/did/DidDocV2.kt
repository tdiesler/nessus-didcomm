package org.nessus.didcomm.did

import id.walt.common.KlaxonWithConverters
import id.walt.crypto.LdVerificationKeyType.Ed25519VerificationKey2018
import id.walt.crypto.LdVerificationKeyType.Ed25519VerificationKey2019
import id.walt.crypto.LdVerificationKeyType.Ed25519VerificationKey2020
import id.walt.crypto.LdVerificationKeyType.JwsVerificationKey2020
import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.diddoc.DIDCommService
import org.didcommx.didcomm.diddoc.DIDDocEncoder
import org.didcommx.didcomm.diddoc.VerificationMethod
import org.nessus.didcomm.did.DidDocV2.Companion.DEFAULT_ACCEPT
import org.nessus.didcomm.service.WaltIdDidDoc

typealias SicpaDidDoc = org.didcommx.didcomm.diddoc.DIDDoc
typealias WaltIdVerificationMethod = id.walt.model.VerificationMethod
typealias WaltIdServiceEndpoint = id.walt.model.ServiceEndpoint

fun DidDocV2.toSicpaDidDoc() =
    SicpaDidDoc(id, context, alsoKnownAs, controller, authentications, assertionMethods, keyAgreements, capabilityInvocations, capabilityDelegations, verificationMethods, didCommServices)

const val DID_CONTEXT_URL: String = "https://www.w3.org/ns/did/v1"

data class DidDocV2(
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
        val DEFAULT_ACCEPT = listOf("didcomm/v2") //, "didcomm/aip2;env=rfc587")

        fun fromSicpaDidDoc(doc: SicpaDidDoc) = DidDocV2(
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

        fun fromWaltIdDidDoc(doc: WaltIdDidDoc): DidDocV2 {

            val verificationMethods = mutableListOf<WaltIdVerificationMethod>()
            doc.verificationMethod?.also { verificationMethods.addAll(it) }

            fun visitVerificationMethod(vm: WaltIdVerificationMethod): String {
                if (!vm.isReference)
                    verificationMethods.add(vm)
                return vm.id
            }

            return DidDocV2(
                doc.id,
                context = doc.context?.let { doc.context } ?: listOf(),
                alsoKnownAs = listOf(),
                controller = listOf(),
                authentications = doc.authentication?.map { visitVerificationMethod(it) } ?: listOf(),
                assertionMethods = doc.assertionMethod?.map { visitVerificationMethod(it) } ?: listOf(),
                keyAgreements = doc.keyAgreement?.map { visitVerificationMethod(it) } ?: listOf(),
                capabilityInvocations = doc.capabilityInvocation?.map { visitVerificationMethod(it) } ?: listOf(),
                capabilityDelegations = doc.capabilityDelegation?.map { visitVerificationMethod(it) } ?: listOf(),
                verificationMethods = verificationMethods.map { it.toVerificationMethod() },
                didCommServices = doc.service?.map { it.toDIDCommService() } ?: listOf())
        }
    }

    fun serviceEndpoint(): String? {
        return didCommServices.map { it.serviceEndpoint }.firstOrNull()
    }

    fun findVerificationMethod(predicate: (vm: VerificationMethod) -> Boolean): VerificationMethod? {
        return verificationMethods.firstOrNull { predicate.invoke(it) }
    }

    fun encodeJson(pretty: Boolean = false): String {
        return DIDDocEncoder.encodeJson(toSicpaDidDoc(), pretty)
    }

    override fun toString(): String {
        return encodeJson()
    }
}

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

fun WaltIdServiceEndpoint.toDIDCommService(): DIDCommService {
    return DIDCommService(
        id = id,
        serviceEndpoint = serviceEndpoint.first(),
        accept = DEFAULT_ACCEPT,
        routingKeys = listOf(),
    )
}
