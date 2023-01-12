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

import org.hyperledger.aries.api.connection.ConnectionRecord
import org.nessus.didcomm.did.Did

class PeerConnectionStore {
    private val storage: MutableMap<String, PeerConnection> = mutableMapOf()

    val connections get() = storage.values.toList()
    fun connections(predicate: (PeerConnection) -> Boolean): List<PeerConnection> {
        return storage.values.filter { predicate.invoke(it) }.toList()
    }

    fun addConnection(conn: PeerConnection) {
        storage[conn.id] = conn
    }

    fun removeConnection(id: String): PeerConnection? {
        return storage.remove(id)
    }

    fun getConnection(id: String): PeerConnection? {
        return storage[id]
    }

    fun findByAlias(alias: String): List<PeerConnection> {
        return connections { c -> c.alias == alias }
    }

    fun findByMyDid(did: Did): List<PeerConnection> {
        return connections { c -> c.myDid == did }
    }

    fun findByTheirDid(did: Did): List<PeerConnection> {
        return connections { c -> c.theirDid == did }
    }
}

enum class ConnectionState(val value: String) {
    INVITATION("invitation"),
    REQUEST("request"),
    ACTIVE("active"),
    COMPLETED("completed"),
    ABANDONED("abandoned"),
    ERROR("error"),
}

data class PeerConnection(
    val id: String,
    val threadId: String,
    val myDid: Did,
    val theirDid: Did,
    val state: ConnectionState,
    val alias: String? = null,
) {
    companion object {
        private fun fromSpec(spec: String): Did {
            if (!spec.startsWith("did:")) {
                return Did.fromSpec("did:sov:$spec")
            }
            return Did.fromSpec(spec)
        }
        fun fromAcapyRecord(cr: ConnectionRecord): PeerConnection {
            val threadId = cr.invitationMsgId
            val state = ConnectionState.valueOf(cr.state.name)
            return PeerConnection(cr.connectionId, threadId, fromSpec(cr.myDid), fromSpec(cr.theirDid), state)
        }
    }
}