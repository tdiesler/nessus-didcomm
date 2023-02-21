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
import com.google.gson.JsonArray
import com.google.gson.JsonObject
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.diddoc.DIDCommService
import org.didcommx.didcomm.diddoc.DIDDoc
import org.didcommx.didcomm.diddoc.VerificationMethod
import org.nessus.didcomm.util.gsonPretty

object DIDDocEncoder {

    private val gson get() = GsonBuilder().create()

    /**
     * Encode according to
     * https://www.w3.org/TR/did-core/#did-document-properties
     */
    fun encodeJson(doc: DIDDoc, pretty: Boolean = false): String {
        val jsonObj = JsonObject()

        // id
        jsonObj.addProperty("id", doc.did)

        // authentication
        if (doc.authentications.isNotEmpty()) {
            val authentication = doc.authentications.fold(JsonArray()) { arr, el -> arr.add(el); arr }
            jsonObj.add("authentication", authentication)
        }

        // keyAgreement
        if (doc.keyAgreements.isNotEmpty()) {
            val keyAgreement = doc.keyAgreements.fold(JsonArray()) { arr, el -> arr.add(el); arr }
            jsonObj.add("keyAgreement", keyAgreement)
        }

        // verificationMethod
        if (doc.verificationMethods.isNotEmpty()) {
            val verificationMethod = doc.verificationMethods.fold(JsonArray()) { arr, el -> arr.add(encodeVerificationMethod(el)); arr }
            jsonObj.add("verificationMethod", verificationMethod)
        }

        // service
        if (doc.didCommServices.isNotEmpty()) {
            val service = doc.didCommServices.fold(JsonArray()) { arr, el -> arr.add(encodeDidCommService(el)); arr }
            jsonObj.add("service", service)
        }

        return if (pretty)
            gsonPretty.toJson(jsonObj)
        else
            gson.toJson(jsonObj)
    }

    private fun encodeVerificationMethod(vm: VerificationMethod): JsonObject {
        val jsonObj = JsonObject()

        // id
        jsonObj.addProperty("id", vm.id)

        // type
        jsonObj.addProperty("type", when(vm.type) {
            VerificationMethodType.ED25519_VERIFICATION_KEY_2018 -> "Ed25519VerificationKey2018"
            VerificationMethodType.ED25519_VERIFICATION_KEY_2020 -> "Ed25519VerificationKey2020"
            VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019 -> "X25519KeyAgreementKey2019"
            VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020 -> "X25519KeyAgreementKey2020"
            VerificationMethodType.JSON_WEB_KEY_2020 -> "JsonWebKey2020"
            VerificationMethodType.OTHER -> throw IllegalStateException("Unsupported verification type: ${vm.type}")
        })

        // controller
        jsonObj.addProperty("controller", vm.controller)

        // verification material
        val materialFormat = vm.verificationMaterial.format
        val materialValue = vm.verificationMaterial.value
        when(materialFormat) {
            VerificationMaterialFormat.JWK -> {
                jsonObj.add("publicKeyJwk", gson.fromJson(materialValue, JsonObject::class.java))
            }
            VerificationMaterialFormat.BASE58 -> {
                jsonObj.addProperty("publicKeyBase58", materialValue)
            }
            VerificationMaterialFormat.MULTIBASE -> {
                jsonObj.addProperty("publicKeyMultibase", materialValue)
            }
            VerificationMaterialFormat.OTHER -> throw IllegalStateException("Unsupported verification material: ${materialFormat}")
        }
        return jsonObj
    }

    private fun encodeDidCommService(srv: DIDCommService): JsonObject {
        val jsonObj = JsonObject()

        // id
        jsonObj.addProperty("id", srv.id)

        // type
        jsonObj.addProperty("type", "DIDCommMessaging")

        // accept
        if (srv.accept?.isNotEmpty() == true) {
            val accept = srv.accept?.fold(JsonArray()) { arr, el -> arr.add(el); arr }
            jsonObj.add("accept", accept)
        }

        // routingKeys
        if (srv.routingKeys.isNotEmpty()) {
            val routingKeys = srv.routingKeys.fold(JsonArray()) { arr, el -> arr.add(el); arr }
            jsonObj.add("routingKeys", routingKeys)
        }

        // serviceEndpoint
        jsonObj.addProperty("serviceEndpoint", srv.serviceEndpoint)

        return jsonObj
    }
}
