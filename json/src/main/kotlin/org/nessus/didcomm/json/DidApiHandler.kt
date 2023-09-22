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
package org.nessus.didcomm.json

import kotlinx.serialization.json.Json
import org.nessus.didcomm.json.model.DidData
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.service.DidOptions
import org.nessus.didcomm.service.DidPeerOptions

object DidApiHandler: AbstractApiHandler() {

    fun createDid(payload: String): Did {
        val data = Json.decodeFromString<DidData>(payload)
        checkNotNull(data.ownerId) { "No ownerId" }
        val owner = assertWallet(data.ownerId)
        val endpointUrl = owner.endpointUrl
        val options = when (data.method) {
            DidMethod.PEER -> {
                val numalgo = data.options["numalgo"] as? Int ?: 2
                DidPeerOptions(numalgo, endpointUrl = endpointUrl)
            }
            else -> {
                DidOptions(endpointUrl = endpointUrl)
            }
        }
        return owner.createDid(data.method, options = options)
    }

    fun listDids(payload: String): List<Did> {
        val data = Json.decodeFromString<DidData>(payload)
        checkNotNull(data.ownerId) { "No ownerId" }
        val owner = assertWallet(data.ownerId)
        return owner.dids.filter { data.method == null || it.method == data.method }
    }
}
