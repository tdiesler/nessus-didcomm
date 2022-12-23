package org.nessus.didcomm.itest

import org.junit.jupiter.api.BeforeAll
import org.junit.jupiter.api.Test
import org.nessus.didcomm.agent.aries.AriesAgentService
import org.nessus.didcomm.agent.aries.AriesWalletService
import org.nessus.didcomm.service.ServiceRegistry
import org.nessus.didcomm.service.walletService
import org.nessus.didcomm.wallet.LedgerRole
import org.nessus.didcomm.wallet.NessusWallet
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * Onboard ENDORSER through TRUSTEE
 * https://github.com/tdiesler/nessus-didcomm/issues/9
 */
class OnboardEndorserTest : AbstractAriesTest() {

    companion object {
        @BeforeAll
        @JvmStatic
        internal fun beforeAll() {
            ServiceRegistry.addService(AriesAgentService())
            ServiceRegistry.addService(AriesWalletService())
        }
    }

    @Test
    fun testOnboardFaber() {

        // ./wallet-bootstrap --create Government --ledger-role TRUSTEE
        val gov = getWalletByName(GOVERNMENT)!!

        // ./wallet-bootstrap --create Faber --ledger-role ENDORSER
        val maybeFaber = getWalletByName(FABER)
        val faber = maybeFaber ?: NessusWallet.builder(FABER)
                .ledgerRole(LedgerRole.ENDORSER)
                .trusteeWallet(gov)
                .build()

        try {

            val pubDid = faber.publicDid
            assertNotNull(pubDid, "No public Did")
            assertTrue(pubDid.startsWith("did:sov"), "Unexpected public did: $pubDid")

        } finally {
            if (maybeFaber == null)
                walletService().removeWallet(faber.walletId)
        }
    }
}
