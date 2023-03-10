package org.nessus.didcomm.did

import com.google.gson.annotations.SerializedName

data class DidDocV1(
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
        return Did.fromUri(didSpec, didVerkey)
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