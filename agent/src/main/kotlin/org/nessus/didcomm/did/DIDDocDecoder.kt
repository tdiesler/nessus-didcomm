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
package org.nessus.didcomm.did

import com.google.gson.GsonBuilder
import com.google.gson.JsonObject
import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.diddoc.DIDCommService
import org.didcommx.didcomm.diddoc.DIDDoc
import org.didcommx.didcomm.diddoc.VerificationMethod

object DIDDocDecoder {

    private val gson get() = GsonBuilder().create()

    /**
     * Decode according to
     * https://www.w3.org/TR/did-core/#did-document-properties
     */
    fun decodeJson(doc: String): DIDDoc {
        val jsonObj = gson.fromJson(doc, JsonObject::class.java)

        // id
        val id = jsonObj["id"].asString

        // keyAgreement
        val keyAgreements = jsonObj.get("keyAgreement")
            ?.let { it.asJsonArray.map { el -> el.asString }}
            ?: listOf()

        // authentication
        val authentications = jsonObj.get("authentication")
            ?.let { it.asJsonArray.map { el -> el.asString }}
            ?: listOf()

        // verificationMethod
        val verificationMethods = jsonObj.get("verificationMethod")
            ?.let { it.asJsonArray.map { el -> decodeVerificationMethod(el.asJsonObject) }}
            ?: listOf()

        // service
        val didCommServices = jsonObj.get("service")
            ?.let { it.asJsonArray.map { el -> decodeDIDCommService(el.asJsonObject) }}
            ?: listOf()

        return DIDDoc(
            did = id,
            keyAgreements = keyAgreements,
            authentications = authentications,
            verificationMethods = verificationMethods,
            didCommServices = didCommServices)
    }

    private fun decodeVerificationMethod(obj: JsonObject): VerificationMethod {
        val id = obj["id"].asString
        val methodType = when(val type = obj["type"].asString) {
            "Ed25519VerificationKey2018" -> VerificationMethodType.ED25519_VERIFICATION_KEY_2018
            "Ed25519VerificationKey2020" -> VerificationMethodType.ED25519_VERIFICATION_KEY_2020
            "X25519KeyAgreementKey2019" -> VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019
            "X25519KeyAgreementKey2020" -> VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020
            "JsonWebKey2020" -> VerificationMethodType.JSON_WEB_KEY_2020
            else -> throw IllegalStateException("Unsupported verification type: $type")
        }
        val material = when {
            obj["publicKeyJwk"] != null -> VerificationMaterial(VerificationMaterialFormat.JWK, gson.toJson(obj["publicKeyJwk"]))
            obj["publicKeyBase58"] != null -> VerificationMaterial(VerificationMaterialFormat.BASE58, obj["publicKeyBase58"].asString)
            obj["publicKeyMultibase"] != null -> VerificationMaterial(VerificationMaterialFormat.MULTIBASE, obj["publicKeyMultibase"].asString)
            else -> throw IllegalStateException("Unsupported verification material: $obj")
         }
        val controller = obj["controller"].asString
        return VerificationMethod(id, methodType, material, controller)
    }

    private fun decodeDIDCommService(obj: JsonObject): DIDCommService {
        val id = obj["id"].asString
        val serviceEndpoint = obj["serviceEndpoint"].asString
        val accept = obj["accept"]?.let { it.asJsonArray.map { el -> el.asString }} ?: listOf()
        val routingKeys = obj["routingKeys"]?.let { it.asJsonArray.map { el -> el.asString }} ?: listOf()
        return DIDCommService(id, serviceEndpoint, routingKeys, accept)
    }
}
