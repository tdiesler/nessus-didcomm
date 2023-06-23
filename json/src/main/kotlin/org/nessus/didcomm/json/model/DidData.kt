/*-
 * #%L
 * Nessus DIDComm :: ITests
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
package org.nessus.didcomm.json.model

import kotlinx.serialization.Serializable
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import org.nessus.didcomm.json.AnyValueSerializer
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.DidPeer

@Serializable
data class DidData(
    val method: DidMethod? = null,
    val id: String? = null,
    val verkey: String? = null,
    val options: Map<String, @Serializable(with = AnyValueSerializer::class) Any> = emptyMap()) {

    companion object {
        fun fromDid(did: Did): DidData {
            val options = mutableMapOf<String, Any>()
            if (did is DidPeer) {
                options["numalgo"] = did.numalgo
            }
            return DidData(did.method, did.id, did.verkey, options)
        }
    }

    fun toJson() = Json.encodeToString(this)
}
