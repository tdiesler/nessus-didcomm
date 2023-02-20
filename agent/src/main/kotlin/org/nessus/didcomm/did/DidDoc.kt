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

import org.nessus.didcomm.util.gson

class DidDoc {

    val optV1: DidDocV1?
    val optV2: DidDocV2?

    constructor(docV1: DidDocV1) {
        this.optV1 = docV1
        this.optV2 = null
    }

    constructor(docV2: DidDocV2) {
        this.optV1 = null
        this.optV2 = docV2
    }

    val isV1 get() = optV1 != null
    val actV1: DidDocV1
        get() = run {
        checkNotNull(optV1) { "Not a Did Document V1" }
        return optV1
    }

    val isV2 get() = optV2 != null
    val actV2: DidDocV2
        get() = run {
        checkNotNull(optV2) { "Not a Did Document V2" }
        return optV2
    }

    val id get() = optV1?.id ?: actV2.id

    fun serviceEndpoint(): String? {
        return when {
            isV1 -> actV1.serviceEndpoint()
            else -> actV2.serviceEndpoint()
        }
    }

    fun shortString(): String {
        return "[id=${id}]"
    }

    override fun toString(): String {
        return when {
            isV1 -> gson.toJson(actV1)
            else -> gson.toJson(actV2)
        }
    }
}
