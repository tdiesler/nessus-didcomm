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
import java.util.*

enum class LedgerRole {
    TRUSTEE,
    ENDORSER
}

enum class DidMethod(val value: String) {
    KEY("key"),
    SOV("sov");

    fun supportedAlgorithms() : Set<KeyAlgorithm> {
        return setOf(KeyAlgorithm.EdDSA_Ed25519)
    }
}

enum class WalletAgent(val value: String) {
    ACAPY("aca-py"),
    NESSUS("nessus")
}

enum class WalletType(val value: String) {
    IN_MEMORY("in_memory"),
    INDY("indy")
}

fun createUUID(): String {
    return UUID.randomUUID().toString()
}

/**
 * A NessusWallet gives access to wallet information as known by the agent.
 */
class NessusWallet(
    val walletId: String,
    val walletAgent: WalletAgent,
    val walletType: WalletType,
    val walletName: String? = null,
    val authToken: String? = null,
) {

    val publicDid: Did?
        get() =
            WalletService.getService().publicDid(this)

    override fun toString(): String {
        var redactedToken: String? = null
        if (authToken != null)
            redactedToken = authToken.substring(0, 6) + "..." + authToken.substring(authToken.length - 6)
        return "NessusWallet(id='$walletId', agent=$walletAgent, type=$walletType, name=$walletName, authToken=$redactedToken, publicDid=$publicDid)"
    }

    fun createDid(method: DidMethod? = null, algorithm: KeyAlgorithm? = null, seed: String? = null): Did {
        return WalletService.getService().createDid(this, method, algorithm, seed)
    }

    // -----------------------------------------------------------------------------------------------------------------

    data class Builder (var walletName: String? = null) {
        var didMethod: DidMethod? = null
        var walletAgent: WalletAgent? = null
        var walletType: WalletType? = null
        var walletKey: String? = null
        var ledgerRole: LedgerRole? = null
        var trusteeWallet: NessusWallet? = null
        var publicDid: Boolean = false

        fun didMethod(didMethod: DidMethod?) = apply { this.didMethod = didMethod }
        fun walletAgent(walletAgent: WalletAgent?) = apply { this.walletAgent = walletAgent }
        fun walletType(walletType: WalletType?) = apply { this.walletType = walletType }
        fun walletKey(walletKey: String?) = apply { this.walletKey = walletKey }
        fun ledgerRole(ledgerRole: LedgerRole?) = apply { this.ledgerRole = ledgerRole }
        fun trusteeWallet(trusteeWallet: NessusWallet?) = apply { this.trusteeWallet = trusteeWallet }
        fun publicDid(publicDid: Boolean) = apply { this.publicDid = publicDid }
        fun build(): NessusWallet = WalletService.getService().createWallet(this)
    }
}
