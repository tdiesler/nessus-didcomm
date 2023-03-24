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

class Model {

    internal val walletsMap: MutableMap<String, Wallet> = mutableMapOf()

    val wallets
        get() = walletsMap.values.toList()

    fun addWallet(wallet: Wallet) {
        check(!walletsMap.containsKey(wallet.id)) { "Wallet already exists: ${wallet.id}" }
        walletsMap[wallet.id] = wallet
    }

    fun removeWallet(id: String): Wallet? {
        return walletsMap.remove(id)
    }
}

