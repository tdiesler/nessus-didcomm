package org.nessus.didcomm.model

import com.google.gson.annotations.SerializedName
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.model.InvitationState.DONE
import org.nessus.didcomm.model.InvitationState.INITIAL
import org.nessus.didcomm.model.InvitationState.RECEIVED
import org.nessus.didcomm.util.gson

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

class InvitationV1(
    @SerializedName("@id")
    val id: String,
    @SerializedName("@type")
    val type: String,
    val label: String,
    val accept: List<String>,
    @SerializedName("handshake_protocols")
    val handshakeProtocols: List<String>,
    val services: List<Invitation.Service>,
) {

    companion object {
        fun fromJson(json: String): InvitationV1 {
            return gson.fromJson(json, InvitationV1::class.java).validate()
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

    fun validate(): InvitationV1 {
        state = state ?: INITIAL
        val service = (services).firstOrNull { it.type == "did-communication" }
        checkNotNull(service) { "Cannot find service of type 'did-communication' in: $this"}
        check(service.recipientKeys.size == 1) { "Unexpected number of recipientKeys: $this" }
        checkNotNull(state) { "No state" }
        return this
    }

    fun invitationKey(idx: Int = 0): String {
        return recipientDid(idx).verkey
    }

    fun recipientDid(idx: Int = 0): Did {
        check(services.size > idx) { "No services[$idx].recipientKeys" }
        check(services[idx].recipientKeys.isNotEmpty()) { "No recipient keys" }
        check(services[idx].recipientKeys.size == 1) { "Multiple recipient keys" }
        return Did.fromSpec(services[idx].recipientKeys[0])
    }

    fun recipientServiceEndpoint(idx: Int = 0): String {
        check(services.size > idx) { "No services[$idx].serviceEndpoint" }
        return services[idx].serviceEndpoint
    }

    fun shortString(): String {
        return "[key=${invitationKey()}, url=${recipientServiceEndpoint()}]"
    }

    override fun toString(): String {
        return gson.toJson(this)
    }
}