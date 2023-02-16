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

import io.kotest.matchers.shouldBe
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.StorageType
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.wallet.AcapyWallet
import org.nessus.didcomm.model.LedgerRole

/**
 * Onboard ENDORSER through TRUSTEE
 */
class OnboardFaberTest : AbstractITest() {

    @Test
    fun testOnboardFaber() {

        // ./wallet-bootstrap --create Government --ledger-role TRUSTEE
        val gov = getWalletByAlias(Government.name) as AcapyWallet

        // ./wallet-bootstrap --create Faber --ledger-role ENDORSER
        val maybeFaber = getWalletByAlias(Faber.name)
        val faber = maybeFaber ?: Wallet.Builder(Faber.name)
            .agentType(AgentType.ACAPY)
            .ledgerRole(LedgerRole.ENDORSER)
            .storageType(StorageType.INDY)
            .trusteeWallet(gov)
            .build()

        try {

            val pubDid = faber.getPublicDid()
            pubDid?.method shouldBe DidMethod.SOV

        } finally {
            if (maybeFaber == null) {
                walletService.removeWallet(faber.id)
            }
        }
    }
}
