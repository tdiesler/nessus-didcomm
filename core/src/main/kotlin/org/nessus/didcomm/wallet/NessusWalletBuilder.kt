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

import org.nessus.didcomm.service.walletService

class NessusWalletBuilder(private var walletName: String? = null) {

    private var didMethod: DIDMethod? = null
    private var walletType: WalletType? = null
    private var ledgerRole: LedgerRole? = null
    private var trusteeWallet: NessusWallet? = null

    fun walletName(walletName: String): NessusWalletBuilder {
        this.walletName = walletName
        return this
    }

    fun walletType(walletType: WalletType?): NessusWalletBuilder {
        this.walletType = walletType
        return this
    }

    fun didMethod(didMethod: DIDMethod?): NessusWalletBuilder {
        this.didMethod = didMethod
        return this
    }

    fun ledgerRole(ledgerRole: LedgerRole?): NessusWalletBuilder {
        this.ledgerRole = ledgerRole
        return this
    }

    fun trusteeWallet(trusteeWallet: NessusWallet?): NessusWalletBuilder {
        this.trusteeWallet = trusteeWallet
        return this
    }

    fun build(): NessusWallet {
        val config: Map<String, Any?> = mapOf(
            "walletName" to walletName,
            "walletType" to walletType,
            "didMethod" to didMethod,
            "ledgerRole" to ledgerRole,
            "trusteeWallet" to trusteeWallet,
        )
        return walletService().createWallet(walletName, config)
    }
}
