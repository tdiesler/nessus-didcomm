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
import org.nessus.didcomm.wallet.DidMethod
import java.security.PrivateKey
import java.security.PublicKey

class Did {

    val id: String
    val method: DidMethod
    val algorithm: KeyAlgorithm
    val verkey: String

    constructor(id: String, method: DidMethod, algorithm: KeyAlgorithm, verkey: String) {
        this.id = id.substring(id.lastIndexOf(':') + 1)
        this.method = method
        this.algorithm = algorithm
        this.verkey = verkey
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
        return qualified
    }
}

data class DidInfo(
    val did: Did,
    val pubKey: PublicKey?,
    val prvKey: PrivateKey?)
