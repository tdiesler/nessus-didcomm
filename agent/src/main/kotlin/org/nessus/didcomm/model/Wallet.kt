/*-
 * #%L
 * Nessus DIDComm :: Agent
 * %%
 * Copyright (C) 2022 - 2023 Nessus
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package org.nessus.didcomm.model

import com.google.gson.JsonObject
import com.google.gson.annotations.SerializedName
import mu.KotlinLogging
import org.nessus.didcomm.model.ConnectionState.*
import org.nessus.didcomm.service.DidOptions
import org.nessus.didcomm.service.WalletPlugin
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.gsonPretty

enum class AgentType(val value: String) {
    @SerializedName("AcaPy")
    ACAPY("AcaPy"),
    @SerializedName("Nessus")
    NESSUS("Nessus");
    companion object {
        fun fromValue(value: String) = AgentType.valueOf(value.uppercase())
    }
}

enum class StorageType(val value: String) {
    IN_MEMORY("in_memory"),
    INDY("indy");
    companion object {
        fun fromValue(value: String) = StorageType.valueOf(value.uppercase())
    }
}

enum class LedgerRole {
    TRUSTEE,
    ENDORSER
}

/**
 * A Wallet provides access to general wallet functionality.
 *
 * All work is delegated to the WalletService, which maintains the set
 * of all wallets known by the system.
 *
 * Agent specific functionality is handled by a WalletPlugin which is a
 * stateful entity associated with this wallet
 */
abstract class Wallet(
    val id: String,
    val name: String,
    val agentType: AgentType,
    val storageType: StorageType,
    val endpointUrl: String,
    val options: Map<String, String> = mapOf(),

    @Transient
    private val didsInternal: MutableList<Did> = mutableListOf(),

    @Transient
    private val invitationsInternal: MutableList<Invitation> = mutableListOf(),

    @Transient
    private val connectionsInternal: MutableList<Connection> = mutableListOf(),

    @Transient
    private val verifiableCredentialsInternal: MutableList<W3CVerifiableCredential> = mutableListOf(),
) {
    companion object {
        private val log = KotlinLogging.logger {}
    }

    internal val walletService get() = WalletService.getService()
    internal abstract val walletPlugin: WalletPlugin

    val dids get() = didsInternal.toList()
    val invitations get() = invitationsInternal.toList()
    val connections get() = connectionsInternal.toList()
    val verifiableCredentials get() = verifiableCredentialsInternal.toList()

    @Transient
    var currentConnection: Connection? = null
        set(pcon) {
            require(pcon?.state == ACTIVE) { "Unexpected connection state: ${pcon?.shortString()}" }
            field = pcon
        }

    @Transient
    internal var internalPublicDid: Did? = null

    var publicDid: Did?
        get() = walletService.getPublicDid(this)
        set(did) = walletService.setPublicDid(this, did)

    fun createDid(method: DidMethod? = null, keyAlias: String? = null, options: DidOptions? = null): Did {
        return walletService.createDid(this, method, keyAlias, options)
    }

    fun addDid(did: Did) {
        // We currently don't support multiple representations for the same verification key
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

    fun findDidByAlias(alias: String?): Did? {
        if (alias == null)
            return null
        alias.toIntOrNull()?.also {
            val idx = alias.toInt()
            return dids[idx]
        }
        return dids.firstOrNull {
            val candidates = listOf(it.id, it.uri, it.verkey).map { c -> c.lowercase() }
            candidates.any { c -> c.startsWith(alias.lowercase()) }
        }
    }

    fun removeDid(did: Did) {
        didsInternal.remove(did)
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
        getConnection(id)?.also {
            connectionsInternal.remove(it)
        }
    }

    open fun removeConnections() {
        walletService.removeConnections(this)
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

    fun addVerifiableCredential(vc: W3CVerifiableCredential) {
        verifiableCredentialsInternal.add(vc)
    }

    fun getVerifiableCredential(id: String): W3CVerifiableCredential? {
        return findVerifiableCredential { "${it.id}" == id }
    }

    fun findVerifiableCredential(predicate: (vc: W3CVerifiableCredential) -> Boolean): W3CVerifiableCredential? {
        return verifiableCredentialsInternal.firstOrNull(predicate)
    }

    fun findVerifiableCredentialByType(type: String): List<W3CVerifiableCredential> {
        return verifiableCredentialsInternal
            .filter { it.isVerifiableCredential }
            .filter { it.hasType(type) }
    }

    fun findVerifiablePresentationByType(type: String): List<W3CVerifiableCredential> {
        return verifiableCredentialsInternal
            .filter { it.isVerifiablePresentation }
            .filter { it.hasType(type) }
    }

    fun encodeJson(pretty: Boolean = false, redacted: Boolean = true): String {
        val encoded = gson.toJson(this)
        val jsonObj = gson.fromJson(encoded, JsonObject::class.java)
        if (redacted && options.isNotEmpty()) {
            val redactedElement = redactedOptions.entries.fold(JsonObject()) { r, (k, v) -> r.addProperty(k, v); r }
            jsonObj.add("options", redactedElement)
        }
        return if (pretty) gsonPretty.toJson(jsonObj) else gson.toJson(jsonObj)
    }

    fun useDidCommV2(): Boolean {
        return agentType != AgentType.ACAPY
    }

    fun shortString(): String {
        return "$name [agent=${agentType.value}, type=$storageType, url=$endpointUrl]"
    }

    override fun toString(): String {
        return "Wallet(id='$id', agent=$agentType, type=$storageType, alias=$name, endpointUrl=$endpointUrl, options=$redactedOptions)"
    }

    private val redactedOptions get() = options.mapValues { (k, v) ->
        when(k) {
            "authToken" -> v.substring(0, 6) + "..." + v.substring(v.length - 6)
            else -> v
        }
    }

    data class WalletConfig(
        val name: String,
        val agentType: AgentType?,
        val storageType: StorageType?,
        val walletKey: String?,
        val ledgerRole: LedgerRole?,
        val trusteeWallet: AcapyWallet?,
        val publicDidMethod: DidMethod?,
        val options: Map<String, String>,
        val mayExist: Boolean,
    )

    data class Builder (var name: String) {
        var agentType: AgentType? = AgentType.NESSUS
        var storageType: StorageType? = null
        var options: MutableMap<String, String> = mutableMapOf()
        var walletKey: String? = null
        var ledgerRole: LedgerRole? = null
        var trusteeWallet: AcapyWallet? = null
        var publicDidMethod: DidMethod? = null
        var mayExist: Boolean = false

        fun agentType(agentType: AgentType?) = apply { this.agentType = agentType }
        fun endpointUrl(url: String?) = apply { url?.also { options["endpointUrl"] = url }}
        fun options(options: Map<String, String>) = apply { this.options.putAll(options) }
        fun storageType(storageType: StorageType?) = apply { this.storageType = storageType }
        fun walletKey(walletKey: String?) = apply { this.walletKey = walletKey }
        fun publicDidMethod(didMethod: DidMethod?) = apply { this.publicDidMethod = didMethod }
        fun ledgerRole(ledgerRole: LedgerRole?) = apply { this.ledgerRole = ledgerRole }
        fun trusteeWallet(trusteeWallet: AcapyWallet?) = apply { this.trusteeWallet = trusteeWallet }
        fun mayExist(mayExist: Boolean) = apply { this.mayExist = mayExist }

        private val walletType = when(agentType!!) {
            AgentType.ACAPY -> AcapyWallet::class
            AgentType.NESSUS -> NessusWallet::class
        }

        fun build(): Wallet {
            val walletService = WalletService.getService()
            return walletService.createWallet(
                WalletConfig(
                    name,
                    agentType,
                    storageType,
                    walletKey,
                    ledgerRole,
                    trusteeWallet,
                    publicDidMethod,
                    options.toMap(),
                    mayExist
                )
            )
        }
    }
}