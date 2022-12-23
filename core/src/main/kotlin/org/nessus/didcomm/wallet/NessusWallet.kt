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

import org.nessus.didcomm.service.ServiceRegistry
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.service.walletService

class WalletException(msg: String) : Exception(msg)

/**
 * A NessusWallet gives acces to wallet information as known by the agent.
 */
class NessusWallet(
    val walletId: String,
    val walletName: String,
    val accessToken: String? = null,
) {
    companion object {
        fun builder(name: String): NessusWalletBuilder {
            return NessusWalletBuilder(name)
        }
    }

    val publicDid: String?
        get() = walletService().publicDid(this)

    // [TODO] override toString with redacted values

    // -----------------------------------------------------------------------------------------------------------------

}
