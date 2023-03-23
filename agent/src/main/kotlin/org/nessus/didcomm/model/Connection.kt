package org.nessus.didcomm.model

import id.walt.crypto.encodeBase58
import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.service.ModelService
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
}

private val dummyBase58 = ByteArray(32).encodeBase58()
private val dummyDid = Did(dummyBase58.drop(16), DidMethod.SOV, dummyBase58)

class Connection(
    val id: String,
    val agent: AgentType,
    val invitationKey: String,

    myDid: Did,

    @get:Synchronized
    @set:Synchronized
    var myRole: ConnectionRole,

    @get:Synchronized
    @set:Synchronized
    var myLabel: String,

    @get:Synchronized
    @set:Synchronized
    var myEndpointUrl: String,

    theirDid: Did?,

    @get:Synchronized
    @set:Synchronized
    var theirRole: ConnectionRole,

    @get:Synchronized
    @set:Synchronized
    var theirLabel: String?,

    @get:Synchronized
    @set:Synchronized
    var theirEndpointUrl: String?,

    @get:Synchronized
    @set:Synchronized
    var state: ConnectionState,
) {
    companion object {
        private val log = KotlinLogging.logger {}
    }

    @get:Synchronized
    @set:Synchronized
    var myDid: Did = myDid
        set(did) {
            log.info { "Rotate myDid: ${field.uri} => ${did.uri}" }
            field = did
        }

    @get:Synchronized
    @set:Synchronized
    var theirDid: Did = theirDid ?: dummyDid
        set(did) {
            if (field != dummyDid) {
                log.info { "Rotate theirDid: ${field.uri} => ${did.uri}" }
            }
            field = did
        }

    private val modelService get() = ModelService.getService()

    val myWallet get() = modelService.findWalletByVerkey(myVerkey)
    val theirWallet get() = modelService.findWalletByVerkey(theirVerkey)

    val myVerkey get() = myDid.verkey
    val theirVerkey get() = theirDid.verkey

    val alias get() = "${myWallet?.name}-${theirWallet?.name}"

    fun shortString(): String {
        return "$alias [id=$id, myDid=${myDid.uri}, theirDid=${theirDid.uri}, state=$state]"
    }

    override fun toString(): String {
        return gson.toJson(this)
    }
}