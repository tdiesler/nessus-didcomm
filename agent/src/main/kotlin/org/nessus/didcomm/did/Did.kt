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
import id.walt.crypto.encodeBase58
import org.nessus.didcomm.service.DEFAULT_KEY_ALGORITHM
import org.nessus.didcomm.wallet.DidMethod

class Did {

    val id: String
    val method: DidMethod
    val algorithm: KeyAlgorithm
    val verkey: String?

    constructor(id: String, method: DidMethod, algorithm: KeyAlgorithm, verkey: String?) {
        this.id = id.substring(id.lastIndexOf(':') + 1)
        this.method = method
        this.algorithm = algorithm
        this.verkey = verkey
    }

    companion object {
        fun fromSpec(spec: String): Did {
            val toks = spec.split(':')
            require(toks.size == 3) { "Unexpected number of tokens: $spec" }
            require(toks[0] == "did") { "Unexpected first token: $spec" }
            val method = DidMethod.fromValue(toks[1])
            val verkey = when(method) {
                DidMethod.KEY -> convertMultiBase58BtcToRawKey(toks[2]).encodeBase58()
                DidMethod.SOV -> null
                else -> throw IllegalStateException("Unsupported method: $spec")
            }
            return Did(toks[2], method, DEFAULT_KEY_ALGORITHM, verkey)
        }
    }

    val qualified: String
        get() = "did:${this.method.value}:${this.id}"

    override fun equals(other: Any?): Boolean {
        if (other !is Did) return false
        return qualified == other.qualified
    }

    override fun hashCode(): Int {
        return qualified.hashCode()
    }

    override fun toString(): String {
        return "Did(id=$id, method=$method, algorithm=$algorithm, verkey=$verkey)"
    }
}
