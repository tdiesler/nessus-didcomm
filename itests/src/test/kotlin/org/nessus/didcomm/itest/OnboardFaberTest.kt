/*-
 * #%L
 * Nessus DIDComm :: ITests
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
package org.nessus.didcomm.itest

import org.junit.jupiter.api.Test
import org.nessus.didcomm.wallet.DidMethod
import org.nessus.didcomm.wallet.LedgerRole
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.WalletAgent
import org.nessus.didcomm.wallet.WalletType
import kotlin.test.assertEquals

/**
 * Onboard ENDORSER through TRUSTEE
 * https://github.com/tdiesler/nessus-didcomm/issues/9
 */
class OnboardFaberTest : AbstractIntegrationTest() {

    @Test
    fun testOnboardFaber() {

        // ./wallet-bootstrap --create Government --ledger-role TRUSTEE
        val gov = getWalletByAlias(Government.name) as Wallet

        // ./wallet-bootstrap --create Faber --ledger-role ENDORSER
        val maybeFaber = getWalletByAlias(Faber.name)
        val faber = maybeFaber ?: Wallet.Builder(Faber.name)
            .walletAgent(WalletAgent.ACAPY)
            .ledgerRole(LedgerRole.ENDORSER)
            .walletType(WalletType.INDY)
            .trusteeWallet(gov)
            .build()

        try {

            val pubDid = faber.publicDid
            assertEquals(DidMethod.SOV, pubDid?.method)

        } finally {
            if (maybeFaber == null) {
                walletService.removeWallet(faber.id)
            }
        }
    }
}
