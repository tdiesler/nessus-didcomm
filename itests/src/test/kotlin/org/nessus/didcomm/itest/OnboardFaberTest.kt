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
import org.nessus.didcomm.wallet.NessusWallet
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * Onboard ENDORSER through TRUSTEE
 * https://github.com/tdiesler/nessus-didcomm/issues/9
 */
class OnboardFaberTest : AbstractIntegrationTest() {

    @Test
    fun testOnboardFaber() {

        // ./wallet-bootstrap --create Government --ledger-role TRUSTEE
        val gov = getWalletByName(Government.name)!!

        // ./wallet-bootstrap --create Faber --ledger-role ENDORSER
        val maybeFaber = getWalletByName(Faber.name)
        val faber = maybeFaber ?: NessusWallet.Builder(Faber.name)
            .ledgerRole(LedgerRole.ENDORSER)
            .trusteeWallet(gov)
            .build()

        try {

            val pubDid = faber.publicDid
            assertNotNull(pubDid)
            assertEquals(DidMethod.SOV, pubDid.method)

        } finally {
            if (maybeFaber == null) {
                walletService.removeWallet(faber.walletId)
            }
        }
    }
}
