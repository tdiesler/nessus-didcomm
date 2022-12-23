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
package org.nessus.didcomm.service

import org.didcommx.didcomm.message.Message
import org.nessus.didcomm.wallet.NessusWallet

/**
 * An Agent can create, send, receive DIDComMessages
 */
interface AgentService : Service {

    companion object {
        val type: Class<AgentService> = AgentService::class.java
    }

    override val type: Class<AgentService>
        get() = Companion.type

    fun createMessage(wallet: NessusWallet, type: String, body: Map<String, Any> = mapOf()) : Message
}
