package org.nessus.didcomm.model

import id.walt.crypto.encodeBase58
import mu.KotlinLogging
import org.nessus.didcomm.util.gson

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
    CLOSED,
}

private val dummyBase58 = ByteArray(32).encodeBase58()
private val dummyDid = Did(dummyBase58.drop(16), DidMethod.SOV, dummyBase58)

class Connection(
    val id: String,
    val invitationKey: String,

    myDid: Did,
    val myAgent: String?,
    var myRole: ConnectionRole,
    var myLabel: String,
    var myEndpointUrl: String,

    theirDid: Did?,
    val theirAgent: String?,
    var theirRole: ConnectionRole,
    var theirLabel: String?,
    var theirEndpointUrl: String?,

    var state: ConnectionState,
) {
    companion object {
        private val log = KotlinLogging.logger {}
    }

    var myDid: Did = myDid
        set(did) {
            if (did.uri != field.uri) {
                log.info { "Rotate myDid: ${field.uri} => ${did.uri}" }
                field = did
            }
        }

    var theirDid: Did = theirDid ?: dummyDid
        set(did) {
            if (field != dummyDid) {
                log.info { "Rotate theirDid: ${field.uri} => ${did.uri}" }
            }
            field = did
        }

    val alias get() = "${myLabel}_${theirLabel}"
    val myVerkey get() = myDid.verkey
    val theirVerkey get() = theirDid.verkey

    fun close() {
        state = ConnectionState.CLOSED
    }

    fun shortString(): String {
        return "$alias [id=$id, myDid=${myDid.uri}, theirDid=${theirDid.uri}, state=$state]"
    }

    override fun toString(): String {
        return gson.toJson(this)
    }
}