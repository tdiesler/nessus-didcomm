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
import org.nessus.didcomm.DID
import org.nessus.didcomm.service.ServiceRegistry.walletService

enum class LedgerRole {
    TRUSTEE,
    ENDORSER
}

enum class DIDMethod(val value: String) {
    KEY("key"),
    SOV("sov");

    fun supportedAlgorithms() : Set<KeyAlgorithm> {
        return setOf(KeyAlgorithm.EdDSA_Ed25519)
    }
}

enum class WalletType(val value: String) {
    IN_MEMORY("in_memory"),
    INDY("indy")
}

/**
 * A NessusWallet gives access to wallet information as known by the agent.
 */
class NessusWallet(
    val walletId: String,
    val walletType: WalletType,
    val walletName: String? = null,
    val accessToken: String? = null,
) {

    val publicDid: DID?
        get() =
            walletService().publicDid(this)

    // [TODO] override toString with redacted values

    // -----------------------------------------------------------------------------------------------------------------

}
