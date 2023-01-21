package org.nessus.didcomm.model

import com.google.gson.annotations.SerializedName
import org.nessus.didcomm.wallet.Wallet

data class WalletModel(
    val id: String,
    val name: String,
    val dids: MutableMap<String, DidModel> = mutableMapOf(),
    val invitations: MutableMap<String, Invitation> = mutableMapOf(),
    val connections: MutableMap<String, Connection> = mutableMapOf(),
) {
    companion object {
        fun fromWallet(wallet: Wallet): WalletModel {
            return WalletModel(wallet.id,wallet.name)
        }
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
    val atId: String,
    @SerializedName("@type")
    val atType: String,
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
