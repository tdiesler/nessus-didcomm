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
package org.nessus.didcomm.service

import id.walt.common.prettyPrint
import id.walt.servicematrix.ServiceProvider
import id.walt.services.crypto.CryptoService
import id.walt.services.keystore.KeyStoreService
import id.walt.services.keystore.KeyType
import mu.KotlinLogging
import org.didcommx.didcomm.message.Attachment
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidDocV1
import org.nessus.didcomm.util.decodeBase64Url
import org.nessus.didcomm.util.decodeBase64UrlStr
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeBase64Url
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.selectJson
import org.nessus.didcomm.util.trimJson
import java.util.UUID

class DidDocumentV1Service: NessusBaseService() {
    override val implementation get() = serviceImplementation<DidService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = DidDocumentV1Service()
        override fun getService() = implementation
    }

    private val cryptoService get() = CryptoService.getService()
    private val didService get() = DidService.getService()
    private val keyStore get() = KeyStoreService.getService()

    fun createDidDocument(did: Did, endpointUrl: String): DidDocV1 {

        val template = """
        {
            "@context": "https://w3id.org/did/v1",
            "id": "${did.qualified}",
            "publicKey": [
                {
                    "id": "${did.qualified}#1",
                    "type": "Ed25519VerificationKey2018",
                    "controller": "${did.qualified}",
                    "publicKeyBase58": "${did.verkey}"
                }
            ],
            "authentication": [
                {
                    "type": "Ed25519SignatureAuthentication2018",
                    "publicKey": "${did.qualified}#1"
                }
            ],
            "service": [
                {
                    "id": "${did.qualified};srv",
                    "type": "NessusAgent",
                    "priority": 0,
                    "recipientKeys": [
                        "${did.verkey}"
                    ],
                    "serviceEndpoint": "$endpointUrl"
                }
            ]
        }
        """.trimJson()
        return gson.fromJson(template, DidDocV1::class.java)
    }

    fun createDidDocAttachment(didDocument: DidDocV1, sigDid: Did): Attachment {
        val didDocAttachMap = createDidDocAttachmentMap(didDocument, sigDid)
        val jsonData = Attachment.Data.Json.parse(mapOf("json" to didDocAttachMap))
        return Attachment.Builder("${UUID.randomUUID()}", jsonData)
            .mediaType(DID_DOCUMENT_MEDIA_TYPE)
            .build()
    }

    fun createDidDocAttachmentMap(didDocument: DidDocV1, sigDid: Did): Map<String, Any> {

        val didDocumentJson = gson.toJson(didDocument)
        val didDocument64 = didDocumentJson.toByteArray().encodeBase64Url()

        val octetKeyPair = sigDid.toOctetKeyPair()
        val didKey = keyStore.load(sigDid.verkey, KeyType.PUBLIC).toDidKey()

        val protectedTemplate = """
        {
            "alg": "${octetKeyPair.algorithm}",
            "kid": "${didKey.qualified}",
            "jwk": {
                "kty": "${octetKeyPair.keyType}",
                "crv": "${octetKeyPair.curve}",
                "x": "${octetKeyPair.x}",
                "kid": "${didKey.qualified}"
            }
        }            
        """.trimJson()

        val protected64 = protectedTemplate.toByteArray().encodeBase64Url()

        val data = "$protected64.$didDocument64".toByteArray()
        val keyId = keyStore.load(sigDid.verkey).keyId
        val signature64 = cryptoService.sign(keyId, data).encodeBase64Url()

        return """
        {
            "@id": "${UUID.randomUUID()}",
            "mime-type": "application/json",
            "data": {
              "base64": "$didDocument64",
              "jws": {
                "header": {
                  "kid": "${didKey.qualified}"
                },
                "protected": "$protected64",
                "signature": "$signature64"
              }
            }
          }
        """.decodeJson()
    }

    fun extractDidDocAttachment(attachment: Attachment, verkey: String?): DidDocV1Attachment {
        require(attachment.mediaType == DID_DOCUMENT_MEDIA_TYPE) { "Unexpected media_type: ${attachment.mediaType} "}

        val didDocAttachment = gson.toJson(attachment.data.toJSONObject()["json"])
        checkNotNull(didDocAttachment) {"Cannot find attached did document"}

        return extractDidDocAttachment(didDocAttachment, verkey)
    }

    fun extractDidDocAttachment(attachment: String, verkey: String?): DidDocV1Attachment {

        val didDocument64 = attachment.selectJson("data.base64")
        val jwsProtected64 = attachment.selectJson("data.jws.protected")
        val jwsSignature64 = attachment.selectJson("data.jws.signature")
        val jwsHeaderKid = attachment.selectJson("data.jws.header.kid")
        checkNotNull(didDocument64) { "No 'data.base64'" }
        checkNotNull(jwsProtected64) { "No 'data.jws.protected'" }
        checkNotNull(jwsSignature64) { "No 'data.jws.signature'" }
        checkNotNull(jwsHeaderKid) { "No 'data.jws.header.kid'" }

        val diddocJson = didDocument64.decodeBase64UrlStr() // Contains json whitespace
        val didDocument = gson.fromJson(diddocJson, DidDocV1::class.java)

        val signature = jwsSignature64.decodeBase64Url()
        val data = "$jwsProtected64.$didDocument64".toByteArray()
        log.info { "Extracted Did Document: ${diddocJson.prettyPrint()}" }

        // Verify that all verkeys in the publicKey section
        // are also listed in service.recipientKeys
        val recipientKeys = didDocument.service[0].recipientKeys
        didDocument.publicKey.forEach {
            check(recipientKeys.contains(it.publicKeyBase58))
        }

        val jwsHeaderDid = Did.fromSpec(jwsHeaderKid)
        val publicKeyDid = didDocument.publicKeyDid()

        val signatoryDid = if (verkey != null) {
            val key = keyStore.load(verkey, KeyType.PUBLIC)
            check(cryptoService.verify(key.keyId, signature, data)) { "Did Document signature verification failed with: $verkey" }
            key.toDidKey()
        } else {
            // The JWS header.kid is expected to be the did:key
            // representation of the DidDocument's public key
            check(jwsHeaderDid.verkey == publicKeyDid.verkey) { "Verkey mismatch" }

            // The signatoryDid is already registered when the DidEx Request
            // received here was also created by this agent instance
            if (keyStore.getKeyId(jwsHeaderDid.verkey) == null) {
                didService.registerWithKeyStore(jwsHeaderDid)
            }

            val keyId = keyStore.load(jwsHeaderDid.verkey, KeyType.PUBLIC).keyId
            check(cryptoService.verify(keyId, signature, data)) { "Did Document signature verification failed with: ${jwsHeaderDid.qualified}" }
            jwsHeaderDid
        }

        return DidDocV1Attachment(didDocument, signatoryDid)
    }
}

data class DidDocV1Attachment(
    val didDocument: DidDocV1,
    val signatoryDid: Did
)

