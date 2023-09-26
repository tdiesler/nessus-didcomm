/*-
 * #%L
 * Nessus DIDComm :: Services :: Agent
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
package org.nessus.didcomm.service

import mu.KotlinLogging
import org.nessus.didcomm.model.Model
import org.nessus.didcomm.model.Wallet

object ModelService: ObjectService<ModelService>() {
    val log = KotlinLogging.logger {}

    @JvmStatic
    fun getService() = apply { }

    val model = Model()
    val wallets get() = model.wallets

    fun addWallet(wallet: Wallet) {
        check(findWalletByName(wallet.alias) == null) { "Wallet already exists: ${wallet.alias}" }
        log.info {"Add Wallet: $wallet" }
        model.addWallet(wallet)
    }

    fun getWallet(id: String): Wallet {
        val wallet = model.walletsMap[id]
        checkNotNull(wallet) { "No wallet for: $id" }
        return wallet
    }

    fun findWallet(predicate: (w: Wallet) -> Boolean): Wallet? {
        val result = wallets.filter(predicate)
        return if (result.size == 1) result[0] else null
    }

    fun findWalletByName(name: String): Wallet? {
        return findWallet { it.alias.lowercase() == name.lowercase() }
    }

    fun findWalletByDid(uri: String): Wallet? {
        return findWallet { it.dids.any { d -> d.uri == uri }}
    }

    fun findWalletByVerkey(verkey: String): Wallet? {
        return findWallet { it.dids.any { d -> d.verkey == verkey }}
    }

    fun removeWallet(id: String): Wallet? {
        return model.removeWallet(id)?.also {
            log.info {"Removed Wallet: ${it.shortString()}" }
        }
    }
}
