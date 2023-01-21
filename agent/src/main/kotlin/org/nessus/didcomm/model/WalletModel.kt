package org.nessus.didcomm.model

import com.google.gson.annotations.SerializedName
import org.nessus.didcomm.wallet.Wallet

data class WalletModel(
    val id: String,
    val name: String,
    val dids: MutableList<DidModel> = mutableListOf(),
    val invitations: MutableList<Invitation> = mutableListOf(),
    val connections: MutableList<Connection> = mutableListOf(),
) {
    companion object {
        fun fromWallet(wallet: Wallet): WalletModel {
            return WalletModel(wallet.id,wallet.name)
        }
    }

    fun addInvitation(invitation: Invitation) {
        invitations.add(invitation)
    }

    fun getInvitation(id: String): Invitation? {
        return invitations.firstOrNull { it.id == id }
    }
}

data class DidModel(
    val id: String,
    val method: String,
    val algorithm: String,
    val verkey: String,
) {
    val qualified get() = "did:$method:$id"
}

data class Invitation(
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
) {
    data class Service(
        val id: String,
        val type: String,
        val recipientKeys: List<String>,
        val serviceEndpoint: String,
    )
}

data class Connection(
    val id: String,
    val myDid: String,
    val theirDid: String,
    val state: String,
)
