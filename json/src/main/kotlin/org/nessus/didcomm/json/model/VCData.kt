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

@Serializable
data class VCData(
    val issuerId: String? = null,
    val holderDid: String? = null,
    val credentialId: String? = null,
    val template: String? = null,
    val proofPurpose: String? = "assertionMethod",
    val revocation: Boolean = false,
    val subjectData: Map<String, @Serializable(with = AnyValueSerializer::class) Any>? = null,
) {
    fun toJson() = Json.encodeToString(this)
}
