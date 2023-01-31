/*-
 * #%L
 * Nessus DIDComm :: Agent
 * %%
 * Copyright (C) 2022 - 2023 Nessus
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

import com.google.gson.annotations.SerializedName
import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.model.ConnectionState.*
import org.nessus.didcomm.model.InvitationState.*
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.util.encodeBase58
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet

fun WalletModel.toWallet(): Wallet {
    val walletService = WalletService.getService()
    return walletService.getWallet(this.id) as Wallet
}

data class WalletModel(
    val id: String,
    val name: String,
    val agent: AgentType,
    val endpointUrl: String,
    @SerializedName("dids")
    private val didsInternal: MutableList<Did> = mutableListOf(),
    @SerializedName("invitations")
    private val invitationsInternal: MutableList<Invitation> = mutableListOf(),
    @SerializedName("connections")
    private val connectionsInternal: MutableList<Connection> = mutableListOf(),
) {
    companion object {
        fun fromWallet(wallet: Wallet): WalletModel {
            return WalletModel(wallet.id, wallet.name, wallet.agentType, wallet.endpointUrl)
        }
    }

    @Transient
    private val log = KotlinLogging.logger {}

    val dids get() = didsInternal.toList()
    val invitations get() = invitationsInternal.toList()
    val connections get() = connectionsInternal.toList()

    // Note, we currently don't support multiple
    // representations for the same verification key

    fun addDid(did: Did) {
        check(getDid(did.verkey) == null) { "Did already added" }
        log.info { "Add Did for ${name}: $did" }
        didsInternal.add(did)
    }

    fun getDid(verkey: String): Did? {
        return dids.firstOrNull{ it.verkey == verkey }
    }

    fun hasDid(verkey: String): Boolean {
        return getDid(verkey) != null
    }

    fun findDid(predicate: (d: Did) -> Boolean): Did? {
        return dids.firstOrNull(predicate)
    }

    fun removeDid(verkey: String) {
        getDid(verkey)?.run { didsInternal.remove(this) }
    }

    fun addConnection(con: Connection) {
        check(getConnection(con.id) == null) { "Connection already added" }
        connectionsInternal.add(con)
    }

    fun getConnection(id: String): Connection? {
        return connectionsInternal.firstOrNull { it.id == id }
    }

    fun findConnection(predicate: (c: Connection) -> Boolean): Connection? {
        return connectionsInternal.firstOrNull(predicate)
    }

    fun removeConnection(id: String) {
        getConnection(id)?.run { connectionsInternal.remove(this) }
    }

    fun removeConnections() {
        connectionsInternal.clear()
    }

    fun addInvitation(invitation: Invitation) {
        check(getInvitation(invitation.id) == null) { "Invitation already added" }
        invitationsInternal.add(invitation)
    }

    fun getInvitation(id: String): Invitation? {
        return findInvitation { it.id == id }
    }

    fun findInvitation(predicate: (i: Invitation) -> Boolean): Invitation? {
        return invitationsInternal.firstOrNull(predicate)
    }

    fun removeInvitation(id: String) {
        getInvitation(id)?.run { invitationsInternal.remove(this) }
    }

    fun asString(): String {
        return "$name [agent=${agent.value}, url=$endpointUrl]"
    }
}

enum class InvitationState(val value: String) {
    @SerializedName("initial")
    INITIAL("initial"),
    @SerializedName("receive")
    RECEIVED("receive"),
    @SerializedName("done")
    DONE("done");
    companion object {
        fun fromValue(value: String) = InvitationState.valueOf(value.uppercase())
    }
}

class Invitation(
    @SerializedName("@id")
    val id: String,
    @SerializedName("@type")
    val type: String,
    val label: String,
    val accept: List<String>,
    @SerializedName("handshake_protocols")
    val handshakeProtocols: List<String>,
    val services: List<Service>,
) {

    companion object {
        fun fromJson(json: String): Invitation {
            return gson.fromJson(json, Invitation::class.java).validate()
        }
    }

    var state: InvitationState? = null
        set(next) {
            if (field == null) {
                require(next == INITIAL) { "Invalid state transition: $field => $next" }
            } else {
                val transitions = mapOf(
                    INITIAL to RECEIVED,
                    RECEIVED to DONE)
                require(field == next || transitions[field] == next) { "Invalid state transition: $field => $next" }
            }
            field = next
        }

    data class Service(
        val id: String,
        val type: String,
        val recipientKeys: List<String>,
        val serviceEndpoint: String,
    )

    fun validate():Invitation {
        state = state ?: INITIAL
        val service = (services).firstOrNull { it.type == "did-communication" }
        checkNotNull(service) { "Cannot find service of type 'did-communication' in: $this"}
        check(service.recipientKeys.size == 1) { "Unexpected number of recipientKeys: $this" }
        checkNotNull(state) { "No state" }
        return this
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

    override fun toString(): String {
        return gson.toJson(this)
    }
}

enum class ConnectionRole {
    INVITER,
    INVITEE,
    RESPONDER,
    REQUESTER;
}

enum class ConnectionState {
    INVITATION,
    REQUEST,
    RESPONSE,
    COMPLETED,
    ACTIVE,
}

private val dummyBase58 = ByteArray(32).encodeBase58()
private val dummyDid = Did.fromSpec("did:sov:${dummyBase58.drop(16)}", dummyBase58)

class Connection(
    val id: String,
    val agent: AgentType,
    val invitationKey: String,
    myDid: Did?,
    var myRole: ConnectionRole,
    var myLabel: String,
    var myEndpointUrl: String,
    theirDid: Did?,
    var theirRole: ConnectionRole,
    var theirLabel: String?,
    var theirEndpointUrl: String?,
    var state: ConnectionState,
) {
    @Transient
    private val log = KotlinLogging.logger {}

    var myDid: Did = myDid ?: dummyDid
        set(did) {
            if (field != dummyDid) {
                log.info { "Rotate myDid: ${field.qualified} => ${did.qualified}" }
            }
            field = did
        }

    var theirDid: Did = theirDid ?: dummyDid
        set(did) {
            if (field != dummyDid) {
                log.info { "Rotate theirDid: ${field.qualified} => ${did.qualified}" }
            }
            field = did
        }

    val myVerkey get() = myDid.verkey
    val theirVerkey get() = theirDid.verkey

    override fun toString(): String {
        return gson.toJson(this)
    }
}
