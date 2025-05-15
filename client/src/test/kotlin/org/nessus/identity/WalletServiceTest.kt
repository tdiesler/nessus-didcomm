package org.nessus.identity

import io.kotest.matchers.booleans.shouldBeTrue
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldNotBeBlank
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test
import org.nessus.identity.WalletService.api

class WalletServiceTest {

    var authToken: String? = null
    var walletId: String? = null

    // Authentication --------------------------------------------------------------------------------------------------

    @Test
    fun registerUser() {
        runBlocking {

            // Check whether Alice already exists
            //
            var accessToken: String? = null
            try {
                accessToken = WalletService.login(Alice.toLoginParams())
            } catch (ex: Exception) {
                if (ex.message?.contains("Unknown user") == false) {
                    throw ex
                }
            }

            if (accessToken == null) {
                val success = WalletService.registerUser(Alice.toRegisterUserParams())
                success.shouldBeTrue()
            }
        }
    }

    @Test
    fun userLogin() {
        runBlocking {
            authToken = WalletService.login(Alice.toLoginParams())
            authToken.shouldNotBeBlank()
        }
    }

    // Account ---------------------------------------------------------------------------------------------------------

    @Test
    fun listWallets() {
        runBlocking {
            val token = authLogin(Alice)
            val wallets = WalletService.listWallets(token)
            wallets.shouldNotBeEmpty()
        }
    }

    // Keys ------------------------------------------------------------------------------------------------------------

    @Test
    fun listKeys() {
        runBlocking {
            val token = authLogin(Alice)
            val wid = walletId(token).shouldNotBeNull()
            val keys = WalletService.listKeys(token, wid)
            keys.shouldNotBeEmpty()
        }
    }

    // DIDs ------------------------------------------------------------------------------------------------------------

    @Test
    fun listDids() {
        runBlocking {
            val token = authLogin(Alice)
            val wid = walletId(token).shouldNotBeNull()
            val res: Array<DIDInfo> = WalletService.listDIDs(token, wid)
            res.shouldNotBeEmpty()
        }
    }

    @Test
    fun createDidKey() {
        runBlocking {
            val token = authLogin(Alice)
            val wid = walletId(token).shouldNotBeNull()
            val keys = walletKeys(token, wid)
            val alias = "did:key#${keys.size + 1}"
            val didInfo = WalletService.createDidKey(token, wid, alias, "")
            didInfo.did.shouldNotBeBlank()
        }
    }

    // Logout ----------------------------------------------------------------------------------------------------------

    @Test
    fun userLogout() {
        runBlocking {
            WalletService.logout()
            walletId = null
            authToken = null
        }
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private suspend fun authLogin(user: User): String? {
        if (authToken == null) {
            authToken = WalletService.login(user.toLoginParams())
        }
        return authToken
    }

    private suspend fun walletId(token: String?): String? {
        if (walletId == null) {
            val res = api.accountWallets(token)
            walletId = res.wallets.singleOrNull()?.id
        }
        return walletId
    }

    private suspend fun walletKeys(token: String?, wid: String): List<String> {
        return api.keys(token, wid).map { kr -> kr.keyId.id }
    }
}