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

import id.walt.crypto.convertMultiBase58BtcToRawKey
import id.walt.crypto.decodeBase58
import id.walt.crypto.encodeBase58
import id.walt.model.DidUrl
import org.nessus.didcomm.service.WaltIdDid

enum class DidMethod(val value: String) {
    KEY("key"),
    PEER("peer"),
    SOV("sov");
    companion object {
        fun fromValue(value: String) = DidMethod.valueOf(value.uppercase())
    }
}

typealias WaltIdKeyAlgorithm = id.walt.crypto.KeyAlgorithm

enum class KeyAlgorithm {
    EdDSA_Ed25519;
    companion object {
        fun fromString(algorithm: String): KeyAlgorithm = when (algorithm) {
            "EdDSA", "Ed25519", "EdDSA_Ed25519" -> EdDSA_Ed25519
            else -> throw IllegalArgumentException("Algorithm not supported")
        }
        fun fromWaltIdKeyAlgorithm(algorithm: WaltIdKeyAlgorithm) = KeyAlgorithm.fromString(algorithm.name)
    }
    fun toWaltIdKeyAlgorithm() = WaltIdKeyAlgorithm.fromString(name)
}

val DEFAULT_KEY_ALGORITHM = KeyAlgorithm.EdDSA_Ed25519

class Did(id: String, val method: DidMethod, val algorithm: KeyAlgorithm, val verkey: String) {

    val id: String
    val uri get() = "did:${method.value}:${id}"

    init {
        this.id = id.substring(id.lastIndexOf(':') + 1)
    }

    companion object {
        fun extractDidMethod(uri: String): DidMethod {
            return DidMethod.fromValue(DidUrl.from(uri).method)
        }
        fun fromSpec(spec: String, verkey: String? = null): Did {
            val didUrl = DidUrl.from(spec)
            val identifier = didUrl.identifier
            return when(val method = DidMethod.fromValue(didUrl.method)) {
                DidMethod.KEY -> {
                    val verkeyBytes = convertMultiBase58BtcToRawKey(identifier)
                    check(verkeyBytes.size == 32) { "Invalid verkey: $verkey" }
                    val verkeyFromDid = verkeyBytes.encodeBase58()
                    check(verkey == null || verkey == verkeyFromDid) { "Non matching verkey" }
                    Did(identifier, method, DEFAULT_KEY_ALGORITHM, verkeyFromDid)
                }
                DidMethod.PEER -> {
                    when(identifier[0]) {
                        '0' -> {
                            val verkeyBytes = convertMultiBase58BtcToRawKey(identifier.substring(1))
                            check(verkeyBytes.size == 32) { "Invalid verkey: $verkey" }
                            val verkeyFromDid = verkeyBytes.encodeBase58()
                            check(verkey == null || verkey == verkeyFromDid) { "Non matching verkey" }
                            Did(identifier, method, DEFAULT_KEY_ALGORITHM, verkeyFromDid)
                        }
                        else -> throw IllegalArgumentException( "Unsupported did:peer method: $identifier" )
                    }
                }
                DidMethod.SOV -> {
                    // did:sov uses the first 16 bytes from a (32 byte) verkey
                    check(identifier.decodeBase58().size == 16) { "Invalid did:sov spec: $spec" }
                    checkNotNull(verkey) { "No verkey for: $spec" }
                    val verkeyBytes = verkey.decodeBase58()
                    check(verkeyBytes.size == 32) { "Invalid verkey: $verkey" }
                    val idFromVerkey = verkeyBytes.dropLast(16).toByteArray().encodeBase58()
                    check(identifier == idFromVerkey) { "Invalid verkey for: $spec" }
                    Did(identifier, method, DEFAULT_KEY_ALGORITHM, verkey)
                }
            }
        }
        fun fromWaltIdDid(did: WaltIdDid): Did {
            val verificationMethod = did.verificationMethod?.firstOrNull { it.type.startsWith("Ed25519") }
            checkNotNull(verificationMethod) {"No suitable verification method: ${did.encode()}"}
            val verkey = verificationMethod.publicKeyBase58
            checkNotNull(verkey) {"No verkey in: ${verificationMethod.id}"}
            val didUrl = DidUrl.from(verificationMethod.controller)
            return Did(
                id = didUrl.identifier,
                method = DidMethod.fromValue(didUrl.method),
                algorithm = DEFAULT_KEY_ALGORITHM,
                verkey = verkey)
        }
    }


    @Transient
    private val fingerprint = "$uri.${algorithm.name}.$verkey"

    override fun equals(other: Any?): Boolean {
        if (other !is Did) return false
        return fingerprint == other.fingerprint
    }

    override fun hashCode(): Int {
        return fingerprint.hashCode()
    }

    fun shortString(): String {
        return "$uri [algorithm=$algorithm, verkey=$verkey]"
    }

    override fun toString(): String {
        return "Did(id=$id, method=$method, algorithm=$algorithm, verkey=$verkey)"
    }
}
