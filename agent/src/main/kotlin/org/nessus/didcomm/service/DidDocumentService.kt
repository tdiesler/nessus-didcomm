package org.nessus.didcomm.service

import com.google.gson.JsonObject
import com.google.gson.annotations.SerializedName
import id.walt.common.prettyPrint
import id.walt.crypto.KeyId
import id.walt.servicematrix.ServiceProvider
import id.walt.services.crypto.CryptoService
import id.walt.services.keystore.KeyStoreService
import id.walt.services.keystore.KeyType
import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.util.decodeBase64Url
import org.nessus.didcomm.util.decodeBase64UrlStr
import org.nessus.didcomm.util.encodeBase64Url
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.selectJson
import org.nessus.didcomm.util.trimJson
import java.util.*


class DidDocumentService: NessusBaseService() {
    override val implementation get() = serviceImplementation<DidService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = DidDocumentService()
        override fun getService() = implementation
    }

    private val cryptoService get() = CryptoService.getService()
    private val didService get() = DidService.getService()
    private val keyStore get() = KeyStoreService.getService()

    fun createDidDocument(did: Did, endpointUrl: String): RFC0023DidDocument {

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
        return gson.fromJson(template, RFC0023DidDocument::class.java)
    }

    fun createAttachment(diddocJson: String, sigDid: Did): JsonObject {
        val didDoc = gson.fromJson(diddocJson, RFC0023DidDocument::class.java)
        return createAttachment(didDoc, sigDid)
    }

    fun createAttachment(didDocument: RFC0023DidDocument, sigDid: Did): JsonObject {

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

        val template = """
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
        """.trimJson()

        return gson.fromJson(template, JsonObject::class.java)!!
    }

    fun extractFromAttachment(attachment: String): RFC0023DidDocumentAttachment {

        val didDocument64 = attachment.selectJson("data.base64")
        val jwsProtected64 = attachment.selectJson("data.jws.protected")
        val jwsSignature64 = attachment.selectJson("data.jws.signature")
        val jwsHeaderKid = attachment.selectJson("data.jws.header.kid")
        checkNotNull(didDocument64) { "No 'data.base64'" }
        checkNotNull(jwsProtected64) { "No 'data.jws.protected'" }
        checkNotNull(jwsSignature64) { "No 'data.jws.signature'" }
        checkNotNull(jwsHeaderKid) { "No 'data.jws.header.kid'" }

        val diddocJson = didDocument64.decodeBase64UrlStr() // Contains json whitespace
        val didDocument = gson.fromJson(diddocJson, RFC0023DidDocument::class.java)
        val signatoryDid = Did.fromSpec(jwsHeaderKid)

        val signature = jwsSignature64.decodeBase64Url()
        val data = "$jwsProtected64.$didDocument64".toByteArray()
        log.info { "Extracted Did Document: ${diddocJson.prettyPrint()}" }

        // Verify that all verkeys in the publicKey section
        // are also listed in service.recipientKeys
        val recipientKeys = didDocument.service[0].recipientKeys
        didDocument.publicKey.forEach {
            check(recipientKeys.contains(it.publicKeyBase58))
        }

        fun verifyWith(did: Did): Boolean {
            val keyId = if (keyStore.getKeyId(did.verkey) != null) {
                KeyId(keyStore.getKeyId(did.verkey)!!)
            } else {
                didService.registerWithKeyStore(did)
            }
            return cryptoService.verify(keyId, signature, data)
        }

        check(verifyWith(signatoryDid)) { "Did Document signature verification failed with: $signatoryDid" }

        return RFC0023DidDocumentAttachment(didDocument, signatoryDid)
    }
}

data class RFC0023DidDocumentAttachment(
    val didDocument: RFC0023DidDocument,
    val signatoryDid: Did
)

data class RFC0023DidDocument(
    @SerializedName("@context")
    val atContext: String,
    val id: String,
    val publicKey: List<PublicKey>,
    val authentication: List<Authentication>,
    val service: List<Service>,
) {

    fun publicKeyDid(idx: Int = 0): Did {
        check(publicKey.size > idx) { "No publicKey[$idx]" }
        val didSpec = publicKey[idx].controller as? String
        val didVerkey = publicKey[idx].publicKeyBase58 as? String
        checkNotNull(didSpec) { "No 'publicKey[$idx].controller'" }
        checkNotNull(didVerkey) { "No 'publicKey[$idx].publicKeyBase58'" }
        return Did.fromSpec(didSpec, didVerkey)
    }

    fun serviceEndpoint(idx: Int = 0): String {
        check(service.size > idx) { "No service[$idx]" }
        return service[idx].serviceEndpoint
    }

    data class PublicKey(
        val id: String,
        val type: String,
        val controller: String,
        val publicKeyBase58: String)

    data class Authentication(
        val type: String,
        val publicKey: String)

    data class Service(
        val id: String,
        val type: String,
        val priority: Int,
        val recipientKeys: List<String>,
        val serviceEndpoint: String)
}