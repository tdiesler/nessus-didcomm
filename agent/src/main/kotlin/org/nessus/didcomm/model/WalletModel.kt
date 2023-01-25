package org.nessus.didcomm.model

import com.google.gson.annotations.SerializedName
import id.walt.services.ecosystems.essif.LegalEntityClient.ti
import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.model.ConnectionState.ACTIVE
import org.nessus.didcomm.model.ConnectionState.COMPLETED
import org.nessus.didcomm.model.ConnectionState.REQUEST
import org.nessus.didcomm.model.InvitationState.DONE
import org.nessus.didcomm.model.InvitationState.INITIAL
import org.nessus.didcomm.model.InvitationState.RECEIVED
import org.nessus.didcomm.service.WalletService
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
    val accept: List<String>,
    @SerializedName("handshake_protocols")
    val handshakeProtocols: List<String>,
    @SerializedName("goal_code")
    val goalCode: String,
    val services: List<Service>,
) {

    companion object {
        fun fromJson(json: String): Invitation {
            return gson.fromJson(json, Invitation::class.java).validate()
        }
    }

    var state: InvitationState? = null
        set(next) {
            val transitions = mapOf(
                INITIAL to RECEIVED,
                RECEIVED to DONE)
            require(field == null || field == next || transitions[field] == next) { "Invalid state transition: $field => $next" }
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

enum class ConnectionRole(val value: String) {
    @SerializedName("inviter")
    INVITER("inviter"),
    @SerializedName("invitee")
    INVITEE("invitee"),
    @SerializedName("responder")
    RESPONDER("responder"),
    @SerializedName("requester")
    REQUESTER("requester");
    companion object {
        fun fromValue(value: String) = ConnectionRole.valueOf(value.uppercase())
    }
}

enum class ConnectionState(val value: String) {
    @SerializedName("request")
    REQUEST("request"),
    @SerializedName("completed")
    COMPLETED("completed"),
    @SerializedName("active")
    ACTIVE("active");
    companion object {
        fun fromValue(value: String) = ConnectionState.valueOf(value.uppercase())
    }
}

class Connection(
    val id: String,
    val agent: AgentType,
    val myDid: Did,
    val theirDid: Did,
    val theirLabel: String,
    val theirRole: ConnectionRole,
    val theirEndpointUrl: String,
    val invitationKey: String,
    state: ConnectionState,
) {
    var state: ConnectionState = state
        set(next) {
            val transitions = mapOf(
                REQUEST to COMPLETED,
                COMPLETED to ACTIVE,
                )
            require(field == next || transitions[field] == next) { "Invalid state transition: $field => $next" }
            field = next
        }

    override fun toString(): String {
        return gson.toJson(this)
    }
}
