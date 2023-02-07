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
package org.nessus.didcomm.model

import org.didcommx.didcomm.message.Attachment
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.util.gson

class Invitation {

    val optV1: InvitationV1?
    val optV2: InvitationV2?

    constructor(inviV1: InvitationV1) {
        this.optV1 = inviV1
        this.optV2 = null
    }

    constructor(inviV2: InvitationV2) {
        this.optV1 = null
        this.optV2 = inviV2
    }

    val isV1 get() = optV1 != null
    val actV1: InvitationV1 get() = run {
        checkNotNull(optV1) { "Not an InvitationV1" }
        return optV1
    }

    val isV2 get() = optV2 != null
    val actV2: InvitationV2 get() = run {
        checkNotNull(optV2) { "Not an InvitationV2" }
        return optV2
    }

    val id get() = optV1?.id ?: actV2.id
    val type get() = optV1?.type ?: actV2.type

    val services get() = when {
        isV1 -> actV1.services
        else -> run {
            val attachment = actV2.attachments?.firstOrNull { it.data is Attachment.Data.Json }
            checkNotNull(attachment) { "No json attachment" }
            val json = gson.toJson(attachment.data.toJSONObject()["json"])
            listOf(gson.fromJson(json, Service::class.java))
        }
    }

    fun invitationKey(idx: Int = 0): String {
        return recipientDidKey(idx).verkey
    }

    fun recipientDidKey(idx: Int = 0): Did {
        check(services.size > idx) { "No services[$idx].recipientKeys" }
        check(services[idx].recipientKeys.isNotEmpty()) { "No recipient keys" }
        check(services[idx].recipientKeys.size == 1) { "Multiple recipient keys" }
        return Did.fromSpec(services[idx].recipientKeys[0])
    }

    fun recipientServiceEndpoint(idx: Int = 0): String {
        check(services.size > idx) { "No services[$idx].serviceEndpoint" }
        return services[idx].serviceEndpoint
    }

    fun shortString(): String {
        return "[key=${invitationKey()}, url=${recipientServiceEndpoint()}]"
    }

    override fun toString(): String {
        return when {
            isV1 -> gson.toJson(actV1)
            else -> gson.toJson(actV2.toMessage())
        }
    }

    data class Service(
        val id: String,
        val type: String,
        val recipientKeys: List<String>,
        val serviceEndpoint: String,
    )
}
