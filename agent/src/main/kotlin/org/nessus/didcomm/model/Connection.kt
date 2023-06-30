package org.nessus.didcomm.model

import id.walt.crypto.encodeBase58
import mu.KotlinLogging
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.util.ellipsis
import org.nessus.didcomm.util.gson

enum class ConnectionRole {
    INVITER,
    INVITEE;
}

enum class ConnectionState {
    INVITATION,
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

    theirDid: Did?,
    val theirAgent: String?,
    var theirRole: ConnectionRole,
    var theirLabel: String?,

    var state: ConnectionState,
) {
    companion object {
        private val log = KotlinLogging.logger {}
        private val didService get() = DidService.getService()
    }

    private var theirDidDoc: DidDoc? = null

    val alias get() = "${myLabel}_${theirLabel ?: "Anonymous"}"

    var myDid: Did = myDid
        set(did) {
            if (did.uri != field.uri) {
                log.info { "Rotate myDid: ${field.uri} => ${did.uri}" }
                field = did
            }
        }

    var theirDid: Did = theirDid ?: dummyDid
        set(did) {
            if (field != dummyDid && did.uri != field.uri) {
                log.info { "Rotate theirDid: ${field.uri} => ${did.uri}" }
            }
            field = did
        }

    val myVerkey get() = myDid.verkey
    val theirVerkey get() = theirDid.verkey

    val theirEndpointUrl: String? get() = run {
        if (theirDidDoc == null)
            theirDidDoc = didService.loadOrResolveDidDoc(theirDid.uri)
        val theirDidCommService = theirDidDoc?.didCommServices?.firstOrNull()
        val endpointUrl = theirDidCommService?.serviceEndpoint
        if (endpointUrl == null)
            log.warn { "No serviceEndpoint in: ${theirDidDoc?.encodeJson(true)}" }
        endpointUrl
    }

    fun shortString(): String {
        val ellipses = { did: Did -> did.uri.ellipsis(24) }
        return "$alias [id=$id, myDid=${ellipses(myDid)}, theirDid=${ellipses(theirDid)}, state=$state]"
    }

    override fun toString(): String {
        return gson.toJson(this)
    }
}