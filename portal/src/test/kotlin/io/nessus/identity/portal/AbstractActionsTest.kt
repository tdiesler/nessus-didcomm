package io.nessus.identity.portal

import io.kotest.common.runBlocking
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.ServiceProvider.walletService
import io.nessus.identity.service.User

abstract class AbstractActionsTest {

    companion object {
        val sessions = mutableMapOf<String, LoginContext>()
    }

    fun userLogin(user: User): LoginContext {
        var ctx = sessions[user.email]
        if (ctx == null) {
            ctx = runBlocking {
                walletService.loginWallet(user.toLoginParams())
            }
            sessions[user.email] = ctx
        }
        return ctx
    }
}