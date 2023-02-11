package org.nessus.didcomm.did

import com.nimbusds.jose.jwk.Curve
import id.walt.crypto.KeyId
import id.walt.services.keystore.KeyStoreService
import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.diddoc.DIDCommService
import org.didcommx.didcomm.diddoc.DIDDoc
import org.didcommx.didcomm.diddoc.VerificationMethod
import org.didcommx.didcomm.protocols.routing.PROFILE_DIDCOMM_V2
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.gson

data class DidDocV2(
    val did: String,
    val keyAgreements: List<String>,
    val authentications: List<String>,
    val verificationMethods: List<VerificationMethod>,
    val didCommServices: List<DIDCommService>
) {
    companion object {
        fun fromDIDDoc(doc: DIDDoc): DidDocV2 {
            return DidDocV2(doc.did, doc.keyAgreements, doc.authentications, doc.verificationMethods, doc.didCommServices)
        }
    }

    fun toDIDDoc(): DIDDoc {
        return DIDDoc(did, keyAgreements, authentications, verificationMethods, didCommServices)
    }

    fun toDid(): Did {
        return Did.fromSpec(did)
    }

    fun encodeJson(pretty: Boolean = false): String {
        val jsonMap = gson.toJson(this).decodeJson()
        return jsonMap.encodeJson(pretty)
    }

    fun serviceEndpoint(): String? {
        return didCommServices.map { it.serviceEndpoint }.firstOrNull()
    }

    class Builder(private val did: String) {

        private val authentications: MutableList<String> = mutableListOf()
        private val keyAgreements: MutableList<String> = mutableListOf()
        private val didCommServices: MutableList<DIDCommService> = mutableListOf()
        private val verificationMethods: MutableList<VerificationMethod> = mutableListOf()

        private val didService get() = DidService.getService()
        private val keyStore get() = KeyStoreService.getService()

        fun authentication() = apply {
            val kid = keyStore.getKeyId(did)
            checkNotNull(kid) { "Did not in store: $did" }
            val okp = didService.toOctetKeyPair(did, Curve.Ed25519)
            val keyIdx = authentications.size + 1
            val keyId = "${did}#key-$keyIdx"
            authentications.add(keyId)
            verificationMethods.add(
                VerificationMethod(
                    id = keyId,
                    controller = keyId,
                    type = VerificationMethodType.JSON_WEB_KEY_2020,
                    verificationMaterial = VerificationMaterial(
                        format = VerificationMaterialFormat.JWK,
                        value = okp.toJSONString()
                    )
                )
            )
            if (keyStore.getKeyId(keyId) == null)
                keyStore.addAlias(KeyId(kid), keyId)
        }

        fun keyAgreement() = apply {
            val kid = keyStore.getKeyId(did)
            checkNotNull(kid) { "Did not in store: $did" }
            val okp = didService.toOctetKeyPair(did, Curve.X25519)
            val keyIdx = keyAgreements.size + 1
            val keyId = "${did}#key-x25519-$keyIdx"
            keyAgreements.add(keyId)
            verificationMethods.add(
                VerificationMethod(
                    id = keyId,
                    controller = keyId,
                    type = VerificationMethodType.JSON_WEB_KEY_2020,
                    verificationMaterial = VerificationMaterial(
                        format = VerificationMaterialFormat.JWK,
                        value = okp.toJSONString()
                    )
                )
            )
            if (keyStore.getKeyId(keyId) == null)
                keyStore.addAlias(KeyId(kid), keyId)
        }

        fun didCommService(serviceEndpoint: String) = apply {
            val keyIdx = didCommServices.size + 1
            didCommServices.add(
                DIDCommService(
                    id = "${did}#didcomm-$keyIdx",
                    serviceEndpoint = serviceEndpoint,
                    accept = listOf(PROFILE_DIDCOMM_V2),
                    routingKeys = listOf()
                )
            )
        }

        fun build(): DidDocV2 {
            return DidDocV2(
                did = did,
                authentications = authentications.toList(),
                keyAgreements = keyAgreements.toList(),
                didCommServices = didCommServices.toList(),
                verificationMethods = verificationMethods.toList(),
            )
        }
    }
}