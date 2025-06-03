package io.nessus.identity.portal

import io.kotest.matchers.nulls.shouldNotBeNull
import io.nessus.identity.service.Max
import org.junit.jupiter.api.Test

class WalletActionsTest : AbstractActionsTest() {

    @Test
    fun userLogin() {
        val ctx = userLogin(Max)
        ctx.walletInfo.shouldNotBeNull()
    }
}