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

import com.google.gson.annotations.SerializedName
import id.walt.crypto.KeyAlgorithm
import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.ConnectionState.*
import org.nessus.didcomm.service.WalletPlugin
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.wallet.AcapyWallet
import org.nessus.didcomm.wallet.NessusWallet
import org.nessus.didcomm.wallet.WalletConfig

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
    val options: Map<String, Any> = mapOf(),

    @SerializedName("dids")
    private val didsInternal: MutableList<Did> = mutableListOf(),

    @SerializedName("invitations")
    private val invitationsInternal: MutableList<Invitation> = mutableListOf(),

    @SerializedName("connections")
    private val connectionsInternal: MutableList<Connection> = mutableListOf(),
) {
    @Transient
    private val log = KotlinLogging.logger {}

    internal val walletService get() = WalletService.getService()
    internal abstract val walletPlugin: WalletPlugin

    val dids get() = didsInternal.toList()
    val invitations get() = invitationsInternal.toList()
    val connections get() = connectionsInternal.toList()

    @Synchronized
    fun createDid(method: DidMethod? = null, algorithm: KeyAlgorithm? = null, seed: String? = null): Did {
        return walletService.createDid(this, method, algorithm, seed)
    }

    @Synchronized
    fun addDid(did: Did) {
        // We currently don't support multiple representations for the same verification key
        check(getDid(did.verkey) == null) { "Did already added" }
        log.info { "Add Did for ${name}: $did" }
        didsInternal.add(did)
    }

    @Synchronized
    fun getDid(verkey: String): Did? {
        return dids.firstOrNull{ it.verkey == verkey }
    }

    @Synchronized
    fun getPublicDid(): Did? {
        return walletService.getPublicDid(this)
    }

    @Synchronized
    fun hasDid(verkey: String): Boolean {
        return getDid(verkey) != null
    }

    @Synchronized
    fun findDid(predicate: (d: Did) -> Boolean): Did? {
        return dids.firstOrNull(predicate)
    }

    @Synchronized
    fun removeDid(verkey: String) {
        getDid(verkey)?.run { didsInternal.remove(this) }
    }

    @Synchronized
    fun addConnection(con: Connection) {
        check(getConnection(con.id) == null) { "Connection already added" }
        connectionsInternal.add(con)
    }

    @Synchronized
    fun getConnection(id: String): Connection? {
        return connectionsInternal.firstOrNull { it.id == id }
    }

    @Synchronized
    fun findConnection(predicate: (c: Connection) -> Boolean): Connection? {
        return connectionsInternal.firstOrNull(predicate)
    }

    @Synchronized
    fun removeConnection(id: String) {
        getConnection(id)?.also {
            connectionsInternal.remove(it)
        }
    }

    @Synchronized
    open fun removeConnections() {
        walletService.removeConnections(this)
        connectionsInternal.clear()
    }

    @Synchronized
    fun addInvitation(invitation: Invitation) {
        check(getInvitation(invitation.id) == null) { "Invitation already added" }
        invitationsInternal.add(invitation)
    }

    @Synchronized
    fun getInvitation(id: String): Invitation? {
        return findInvitation { it.id == id }
    }

    @Synchronized
    fun findInvitation(predicate: (i: Invitation) -> Boolean): Invitation? {
        return invitationsInternal.firstOrNull(predicate)
    }

    @Synchronized
    fun removeInvitation(id: String) {
        getInvitation(id)?.run { invitationsInternal.remove(this) }
    }

    fun shortString(): String {
        return "$name [agent=${agentType.value}, url=$endpointUrl]"
    }

    override fun toString(): String {
        val redactedToken = (options["authToken"] as? String)?.run {
            substring(0, 6) + "..." + substring(length - 6)
        }
        return "Wallet(id='$id', agent=$agentType, type=$storageType, alias=$name, endpointUrl=$endpointUrl, options=$options, authToken=$redactedToken)"
    }

    data class Builder (var walletName: String) {
        var agentType: AgentType? = AgentType.NESSUS
        var storageType: StorageType? = null
        var options: MutableMap<String, Any> = mutableMapOf()
        var walletKey: String? = null
        var ledgerRole: LedgerRole? = null
        var trusteeWallet: AcapyWallet? = null
        var publicDidMethod: DidMethod? = null
        var mayExist: Boolean = false

        fun agentType(agentType: AgentType?) = apply { this.agentType = agentType }
        fun options(options: Map<String, Any>) = apply { this.options.putAll(options) }
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
                    walletName,
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

