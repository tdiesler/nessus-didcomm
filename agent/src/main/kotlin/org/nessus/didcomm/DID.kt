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
package org.nessus.didcomm

import id.walt.crypto.KeyAlgorithm
import org.nessus.didcomm.wallet.DIDMethod

val DEFAULT_KEY_ALGORITHM = KeyAlgorithm.EdDSA_Ed25519

enum class KeyType(val value: String) {
    ED25519("ed25519")
}

class DID {

    val did: String
    val method: DIDMethod
    val keyType: KeyType
    val verkey: String
    val qualified: String

    constructor(did: String, method: DIDMethod, keyType: KeyType, verkey: String) {
        this.did = did.substring(did.lastIndexOf(':') + 1)
        this.method = method
        this.keyType = keyType
        this.verkey = verkey
        this.qualified = "did:${method.value}:${this.did}"
    }

    override fun equals(other: Any?): Boolean {
        if (other !is DID) return false
        return qualified == other.qualified
    }

    override fun hashCode(): Int {
        return qualified.hashCode()
    }

    override fun toString(): String {
        return qualified
    }
}
