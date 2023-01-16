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

import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.util.decodeBase58
import org.nessus.didcomm.util.encodeBase58

class PeerConnectionStore {
    private val storage: MutableMap<String, PeerConnection> = mutableMapOf()

    val connections get() = storage.values.toList()
    fun connections(predicate: (PeerConnection) -> Boolean): List<PeerConnection> {
        return storage.values.filter { predicate.invoke(it) }.toList()
    }

    fun addConnection(con: PeerConnection) {
        storage[con.id] = con
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
    ERROR("error");
    companion object {
        fun fromValue(value: String) = ConnectionState.valueOf(value.uppercase())
    }
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
        // [TODO] supply the proper verkey or myDid directly
        private fun dummyVerkey(id: String): String {
            val log = KotlinLogging.logger {}
            val dummyBytes = id.decodeBase58() + ByteArray(16)
            val dummyVerkey = dummyBytes.encodeBase58()
            log.warn { "Supplying dummy verkey: $dummyVerkey" }
            return dummyVerkey
        }
        private fun fromDidSpec(spec: String, verkey: String?): Did {
            require(!spec.startsWith("did:"))
            return Did.fromSpec("did:sov:$spec", verkey)
        }
        fun fromJson(con: Map<String, Any?>): PeerConnection {
            val threadId = con["invitationMsgId"] as String
            val connectionId = con["connectionId"] as String
            val myDid = fromDidSpec(con["myDid"] as String, dummyVerkey(con["myDid"] as String))
            val theirDid = fromDidSpec(con["theirDid"] as String, dummyVerkey(con["theirDid"] as String))
            val state = ConnectionState.fromValue(con["state"] as String)
            return PeerConnection(connectionId, threadId, myDid, theirDid, state)
        }
    }
}