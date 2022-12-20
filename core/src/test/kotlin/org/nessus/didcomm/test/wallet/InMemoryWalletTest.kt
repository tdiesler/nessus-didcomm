package org.nessus.didcomm.test.wallet

import mu.KotlinLogging
import org.junit.jupiter.api.Test
import org.nessus.didcomm.wallet.Wallet
import kotlin.test.Ignore

@Ignore
class InMemoryWalletTest {

    private val log = KotlinLogging.logger {}

    @Test
    fun testCreateLocalDID() {

        // Wallet().createLocalDID("sov")
        Wallet().createLocalDID("sov", seed = "000000000000000000000000Trustee1")
    }
}
