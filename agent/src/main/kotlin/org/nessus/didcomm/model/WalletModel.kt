package org.nessus.didcomm.model

import com.google.gson.annotations.SerializedName
import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.model.ConnectionState.ACTIVE
import org.nessus.didcomm.model.ConnectionState.COMPLETED
import org.nessus.didcomm.model.ConnectionState.REQUEST
import org.nessus.didcomm.model.InvitationState.DONE
import org.nessus.didcomm.model.InvitationState.INITIAL
import org.nessus.didcomm.model.InvitationState.RECEIVED
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.wallet.Wallet

fun WalletModel.toWallet(): Wallet {
    val walletService = WalletService.getService()
    return walletService.getWallet(this.id) as Wallet
}

data class WalletModel(
    val id: String,
    val name: String,
    @SerializedName("dids")
    private val didsInternal: MutableList<Did> = mutableListOf(),
    @SerializedName("invitations")
    private val invitationsInternal: MutableList<Invitation> = mutableListOf(),
    @SerializedName("connections")
    private val connectionsInternal: MutableList<Connection> = mutableListOf(),
) {
    companion object {
        fun fromWallet(wallet: Wallet): WalletModel {
            return WalletModel(wallet.id, wallet.name)
        }
    }

    @Transient
    private val log = KotlinLogging.logger {}

    val dids get() = didsInternal.toList()
    val invitations get() = invitationsInternal.toList()
    val connections get() = connectionsInternal.toList()

    fun addDid(did: Did) {
        if (!hasDid(did.verkey)) {
            log.info { "New DID for ${name}: $did" }
            didsInternal.add(did)
        }
    }

    fun getDid(verkey: String): Did? {
        return dids.firstOrNull{ it.verkey == verkey }
    }

    fun hasDid(verkey: String): Boolean {
        return getDid(verkey) != null
    }

    fun listDids(): List<Did> {
        return dids
    }

    fun addInvitation(invitation: Invitation) {
        check(!hasInvitation(invitation.id)) { "Invitation already added" }
        invitationsInternal.add(invitation)
    }

    fun getInvitation(id: String): Invitation? {
        return invitationsInternal.firstOrNull { it.id == id }
    }

    fun hasInvitation(id: String): Boolean {
        return getInvitation(id) != null
    }

    fun addConnection(con: Connection) {
        check(!hasConnection(con.id)) { "Connection already added" }
        connectionsInternal.add(con)
    }
    
    fun getConnection(id: String): Connection? {
        return connectionsInternal.firstOrNull { it.id == id }
    }

    fun hasConnection(id: String): Boolean {
        return getConnection(id) != null
    }

    fun removeConnections() {
        connectionsInternal.clear()
    }
}

enum class InvitationState {
    INITIAL,
    RECEIVED,
    DONE
}

class Invitation(
    @SerializedName("@id")
    val id: String,
    @SerializedName("@type")
    val type: String,
    @SerializedName("handshake_protocols")
    val handshakeProtocols: List<String>,
    @SerializedName("accept")
    val accept: List<String>,
    @SerializedName("goal_code")
    val goalCode: String,
    @SerializedName("services")
    val services: List<Service>,
    // Transient
    state: InvitationState,
) {

    @SerializedName("state")
    var state: InvitationState = state
        set(next) {
            val transitions = mapOf(
                INITIAL to RECEIVED,
                RECEIVED to DONE)
            require(transitions[field] == next) { "Invalid state transition: $field => $next" }
            field = next
        }

    data class Service(
        val id: String,
        val type: String,
        val recipientKeys: List<String>,
        val serviceEndpoint: String,
    )

    fun getRecipientDid(): Did {
        check(services.isNotEmpty()) { "No services" }
        check(services[0].recipientKeys.isNotEmpty()) { "No recipient keys" }
        return Did.fromSpec(services[0].recipientKeys[0])
    }

    fun getRecipientServiceEndpoint(): String {
        return services[0].serviceEndpoint
    }
}

enum class ConnectionState() {
    REQUEST,
    COMPLETED,
    ACTIVE,
}

class Connection(
    @SerializedName("id")
    val id: String,
    @SerializedName("my_did")
    val myDid: Did,
    @SerializedName("their_did")
    val theirDid: Did,
    @SerializedName("their_endpoint_url")
    val theirEndpointUrl: String,
    // Transient
    state: ConnectionState,
) {
    @SerializedName("state")
    var state: ConnectionState = state
        set(next) {
            val transitions = mapOf(
                REQUEST to COMPLETED,
                COMPLETED to ACTIVE,
                )
            require(transitions[field] == next) { "Invalid state transition: $field => $next" }
            field = next
        }
    
}
