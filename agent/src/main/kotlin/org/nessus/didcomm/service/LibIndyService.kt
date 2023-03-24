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
package org.nessus.didcomm.service

import org.hyperledger.indy.sdk.LibIndy
import org.hyperledger.indy.sdk.wallet.Wallet
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.util.gson

object LibIndyService {

    init {
        // Surefire seems to shadow DYLD_LIBRARY_PATH
        (System.getenv("DYLD_LIBRARY_PATH") ?: System.getenv("LIBINDY_LIBRARY_PATH"))?.run {
            LibIndy.init(this)
        }
    }

    private val indyWallets: MutableMap<String, Wallet> = mutableMapOf()

    fun createAnOpenWallet(alias: String): Wallet {
        val config = walletConfigForAlias(alias)
        Wallet.createWallet(config.first, config.second).get()
        indyWallets[alias] = Wallet.openWallet(config.first, config.second).get()
        return indyWallets[alias] as Wallet
    }

    fun createAndStoreDid(wallet: Wallet, seed: String): Did {
        val seedConfig = gson.toJson(mapOf("seed" to seed))
        val didResult = org.hyperledger.indy.sdk.did.Did.createAndStoreMyDid(wallet, seedConfig).get()
        return Did(didResult.did, DidMethod.SOV, didResult.verkey)
    }

    fun closeAndDeleteWallet(alias: String) {
        indyWallets.remove(alias)?.run {
            this.closeWallet()
            val config = walletConfigForAlias(alias)
            Wallet.deleteWallet(config.first, config.second).get()
        }
    }

    private fun walletConfigForAlias(alias: String): Pair<String, String> {
        return Pair(
            gson.toJson(mapOf("id" to alias)),
            gson.toJson(mapOf("key" to alias + "Key"))
        )
    }
}
