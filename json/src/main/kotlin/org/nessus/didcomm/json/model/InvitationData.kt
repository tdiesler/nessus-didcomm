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
import org.nessus.didcomm.model.DidMethod

@Serializable
data class InvitationData(
    /**
     * Optional inviter id
     */
    val inviterId: String? = null,

    /**
     * Optional inviter id
     */
    val inviteeId: String? = null,

    /**
     * Optional inviter alias
     */
    val inviterAlias: String? = null,

    /**
     * Inviter/Invitee Did URL
     */
    val didUri: String? = null,

    /**
     * Inviter/Invitee DidMethod, when Did is not given
     */
    val didMethod: DidMethod? = null,

    /**
     * Supported options
     * -----------------
     * goal: String
     * goal_code: String
     *
     * https://identity.foundation/didcomm-messaging/spec/v2.0/#goal-codes
     */
    val options: Map<String, @Serializable(with = AnyValueSerializer::class) Any> = emptyMap(),

    /**
     * https://identity.foundation/didcomm-messaging/spec/#standard-message-encoding
     */
    val urlEncoded: String? = null
) {
    fun toJson() = Json.encodeToString(this)
}
