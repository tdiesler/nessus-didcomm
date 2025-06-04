package io.nessus.identity.portal

import io.github.oshai.kotlinlogging.KotlinLogging
import io.kotest.common.runBlocking
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.ServiceProvider.walletService
import io.nessus.identity.service.User

abstract class AbstractActionsTest {

    val log = KotlinLogging.logger {}

    companion object {
        val sessions = mutableMapOf<String, LoginContext>()
    }

    fun userLogin(user: User): LoginContext {
        var ctx = sessions[user.email]
        if (ctx == null) {
            ctx = runBlocking {
                walletService.loginWallet(user.toLoginParams()).also { ctx ->
                    walletService.findDidByPrefix("did:key")?.also {
                        ctx.didInfo = it
                    }
                }
            }
            sessions[user.email] = ctx
        }
        return ctx
    }
}