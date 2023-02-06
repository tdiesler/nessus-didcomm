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

import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.convertMultiBase58BtcToRawKey
import org.nessus.didcomm.service.DEFAULT_KEY_ALGORITHM
import org.nessus.didcomm.util.decodeBase58
import org.nessus.didcomm.util.encodeBase58
import org.nessus.didcomm.wallet.DidMethod

class Did(id: String, val method: DidMethod, val algorithm: KeyAlgorithm, val verkey: String) {

    val id: String
    val qualified get() = "did:${method.value}:${id}"

    init {
        this.id = id.substring(id.lastIndexOf(':') + 1)
    }

    companion object {
        fun fromSpec(spec: String, verkey: String? = null): Did {
            val toks = spec.split(':')
            require(toks.size == 3) { "Unexpected number of tokens: $spec" }
            require(toks[0] == "did") { "Unexpected first token: $spec" }
            val id = toks[2].split('#')[0]
            return when(val method = DidMethod.fromValue(toks[1])) {
                DidMethod.KEY -> {
                    val verkeyBytes = convertMultiBase58BtcToRawKey(toks[2])
                    check(verkeyBytes.size == 32) { "Invalid verkey: $verkey" }
                    val verkeyFromDid = verkeyBytes.encodeBase58()
                    check(verkey == null || verkey == verkeyFromDid) { "Non matching verkey" }
                    Did(id, method, DEFAULT_KEY_ALGORITHM, verkeyFromDid)
                }
                DidMethod.SOV -> {
                    // did:sov uses the first 16 bytes from a (32 byte) verkey
                    check(id.decodeBase58().size == 16) { "Invalid did:sov spec: $spec" }
                    checkNotNull(verkey) { "No verkey for: $spec" }
                    val verkeyBytes = verkey.decodeBase58()
                    check(verkeyBytes.size == 32) { "Invalid verkey: $verkey" }
                    val idFromVerkey = verkeyBytes.dropLast(16).toByteArray().encodeBase58()
                    check(id == idFromVerkey) { "Invalid verkey for: $spec" }
                    Did(id, method, DEFAULT_KEY_ALGORITHM, verkey)
                }
            }
        }
    }


    @Transient
    private val fingerprint = "$qualified.${algorithm.name}.$verkey"

    override fun equals(other: Any?): Boolean {
        if (other !is Did) return false
        return fingerprint == other.fingerprint
    }

    override fun hashCode(): Int {
        return fingerprint.hashCode()
    }

    fun shortString(): String {
        return "[$qualified, verkey=$verkey]"
    }

    override fun toString(): String {
        return "Did(id=$id, method=$method, algorithm=$algorithm, verkey=$verkey)"
    }
}
