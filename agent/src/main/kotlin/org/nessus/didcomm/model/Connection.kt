package org.nessus.didcomm.model

import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.service.ModelService
import org.nessus.didcomm.util.encodeBase58
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
private val dummyDid = Did.fromSpec("did:sov:${dummyBase58.drop(16)}", dummyBase58)

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
    @Transient
    private val log = KotlinLogging.logger {}

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

    val myVerkey get() = myDid.verkey
    val theirVerkey get() = theirDid.verkey

    val alias get() = run {
        val modelService = ModelService.getService()
        val myName = modelService.findWalletByVerkey(myVerkey)?.name
        val theirName = modelService.findWalletByVerkey(theirVerkey)?.name
        "$myName-$theirName"
    }

    fun shortString(): String {
        return "$alias [id=$id, myDid=${myDid.uri}, theirDid=${theirDid.uri}, state=$state]"
    }

    override fun toString(): String {
        return gson.toJson(this)
    }
}