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

import id.walt.model.DidUrl
import org.nessus.didcomm.service.DidService

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
    fun toWaltIdKeyAlgorithm() = WaltIdKeyAlgorithm.fromString(name)
}

val DEFAULT_KEY_ALGORITHM = KeyAlgorithm.EdDSA_Ed25519

open class Did(id: String, val method: DidMethod, val verkey: String) {

    val id: String
    val uri get() = "did:${method.value}:${id}"

    init {
        this.id = id.substring(id.lastIndexOf(':') + 1)
    }

    companion object {
        fun didMethod(uri: String): DidMethod {
            return DidMethod.fromValue(DidUrl.from(uri).method)
        }
        fun fromUri(uri: String, verkey: String? = null): Did {
            val did = if (verkey != null) {
                val didUrl = DidUrl.from(uri)
                val didMethod = DidMethod.fromValue(didUrl.method)
                Did(didUrl.identifier, didMethod, verkey)
            } else {
                val didService = DidService.getService()
                didService.loadOrResolveDid(uri)
            }
            checkNotNull(did) { "Cannot load/resolve: $uri" }
            return did
        }
    }


    @Transient
    private val fingerprint = "$uri.$verkey"

    override fun equals(other: Any?): Boolean {
        if (other !is Did) return false
        return fingerprint == other.fingerprint
    }

    override fun hashCode(): Int {
        return fingerprint.hashCode()
    }

    fun shortString(): String {
        return "$uri [verkey=$verkey]"
    }

    override fun toString(): String {
        return "Did(id=$id, method=$method, verkey=$verkey)"
    }
}

class DidPeer(id: String, method: DidMethod, verkey: String): Did(id, method, verkey) {

    companion object {
        fun fromUri(uri: String): DidPeer? {
            return when {
                uri.startsWith("did:peer:") -> {
                    val didService = DidService.getService()
                    didService.loadOrResolveDid(uri) as? DidPeer
                }
                else -> null
            }
        }
    }

    val numalgo get() = when {
        uri.startsWith("did:peer:0") -> 0
        uri.startsWith("did:peer:2") -> 2
        else -> throw IllegalStateException("Unsupported numalgo: $uri")
    }
}