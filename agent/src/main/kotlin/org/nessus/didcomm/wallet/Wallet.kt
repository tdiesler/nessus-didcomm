/*-
 * #%L
 * Nessus DIDComm :: Core
 * %%
 * Copyright (C) 2022 Nessus
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

package org.nessus.didcomm.wallet

import id.walt.crypto.KeyAlgorithm
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.protocol.Protocol
import org.nessus.didcomm.service.PeerConnection
import org.nessus.didcomm.service.ProtocolId
import org.nessus.didcomm.service.ProtocolService
import org.nessus.didcomm.service.WalletService

enum class LedgerRole {
    TRUSTEE,
    ENDORSER
}

enum class DidMethod(val value: String) {
    KEY("key"),
    SOV("sov");
    companion object {
        fun fromValue(value: String) = DidMethod.valueOf(value.uppercase())
    }
}

enum class WalletAgent(val value: String) {
    ACAPY("AcaPy"),
    NESSUS("Nessus");
    companion object {
        fun fromValue(value: String) = DidMethod.valueOf(value.uppercase())
    }
}

enum class WalletType(val value: String) {
    IN_MEMORY("in_memory"),
    INDY("indy");
    companion object {
        fun fromValue(value: String) = DidMethod.valueOf(value.uppercase())
    }
}

/**
 * A NessusWallet gives access to wallet information as known by the agent.
 */
class Wallet(
    val id: String,
    val alias: String,
    val walletAgent: WalletAgent,
    val walletType: WalletType,
    val endpointUrl: String? = null,
    val authToken: String? = null,
) {

    private val walletService get() = WalletService.getService()

    val publicDid: Did?
        get() = walletService.publicDid(this)

    override fun toString(): String {
        var redactedToken: String? = null
        if (authToken != null)
            redactedToken = authToken.substring(0, 6) + "..." + authToken.substring(authToken.length - 6)
        return "Wallet(id='$id', agent=$walletAgent, type=$walletType, alias=$alias, endpointUrl=$endpointUrl, authToken=$redactedToken)"
    }

    fun createDid(method: DidMethod? = null, algorithm: KeyAlgorithm? = null, seed: String? = null): Did {
        return walletService.createDid(this, method, algorithm, seed)
    }

    fun listDids(): List<Did> {
        return walletService.listDids(this)
    }

    fun <T: Protocol> getProtocol(id: ProtocolId<T>): T {
        val protocols = ProtocolService.getService()
        return protocols.getProtocol(id, walletAgent)
    }

    fun addPeerConnection(con: PeerConnection) {
        walletService.addPeerConnection(this, con)
    }

    fun getPeerConnection(conId: String): PeerConnection? {
        return walletService.getPeerConnection(this, conId)
    }

    fun listPeerConnections(): List<PeerConnection> {
        return walletService.listPeerConnections(this)
    }

    data class Builder (var alias: String) {
        var walletAgent: WalletAgent? = null
        var walletType: WalletType? = null
        var endpointUrl: String? = null
        var walletKey: String? = null
        var publicDidMethod: DidMethod? = null
        var ledgerRole: LedgerRole? = null
        var trusteeWallet: Wallet? = null
        var mayExist: Boolean = false

        fun walletAgent(walletAgent: WalletAgent?) = apply { this.walletAgent = walletAgent }
        fun walletType(walletType: WalletType?) = apply { this.walletType = walletType }
        fun endpointUrl(endpointUrl: String) = apply { this.endpointUrl = endpointUrl }
        fun walletKey(walletKey: String?) = apply { this.walletKey = walletKey }
        fun publicDidMethod(didMethod: DidMethod?) = apply { this.publicDidMethod = didMethod }
        fun ledgerRole(ledgerRole: LedgerRole?) = apply { this.ledgerRole = ledgerRole }
        fun trusteeWallet(trusteeWallet: Wallet?) = apply { this.trusteeWallet = trusteeWallet }
        fun mayExist(mayExist: Boolean) = apply { this.mayExist = mayExist }

        fun build(): Wallet = WalletService.getService().createWallet(
            WalletConfig(alias, walletAgent, walletType, endpointUrl, walletKey, publicDidMethod, ledgerRole, trusteeWallet, mayExist))
    }

    // Private ---------------------------------------------------------------------------------------------------------
}

data class WalletConfig (
    val alias: String,
    val walletAgent: WalletAgent?,
    val walletType: WalletType?,
    val endpointUrl: String?,
    val walletKey: String?,
    val publicDidMethod: DidMethod?,
    val ledgerRole: LedgerRole?,
    val trusteeWallet: Wallet?,
    val mayExist: Boolean)
