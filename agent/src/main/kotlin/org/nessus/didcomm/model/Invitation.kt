package org.nessus.didcomm.model

import com.google.gson.annotations.SerializedName
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.model.InvitationState.INITIAL
import org.nessus.didcomm.model.InvitationState.RECEIVED
import org.nessus.didcomm.model.InvitationState.DONE

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

    fun validate(): Invitation {
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

    fun shortString(): String {
        return "[key=${invitationKey()}, url=${recipientServiceEndpoint()}]"
    }

    override fun toString(): String {
        return gson.toJson(this)
    }
}