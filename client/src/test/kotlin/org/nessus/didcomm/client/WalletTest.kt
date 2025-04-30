package org.nessus.didcomm.client

import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeBlank
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test

open class User(val name: String, val email: String, val password: String)

object Alice : User("Alice", "alice@email.com", "password")

class WalletTest {

    // Authentication --------------------------------------------------------------------------------------------------

    @Test
    fun registerUser() {
        runBlocking {

            // Check whether Alice already exists
            //
            var accessToken: String? = null
            try {
                accessToken = authLogin(Alice)?.token
            } catch (ex: Exception) {
                if (ex.message?.contains("Unknown user") == false) {
                    throw ex
                }
            }

            if (accessToken == null) {
                val res = WalletManager.authRegister(
                    AuthRegisterRequest(
                        type = "email",
                        name = Alice.name,
                        email = Alice.email,
                        password = Alice.password
                    )
                )
                res.shouldNotBeBlank()
            }
        }
    }

    @Test
    fun userLogin() {
        runBlocking {
            val res: AuthLoginResponse = WalletManager.authLogin(
                AuthLoginRequest(
                    type = "email",
                    email = Alice.email,
                    password = Alice.password
                )
            )
            res.id.shouldNotBeBlank()
            res.username.shouldNotBeBlank()
            res.token.shouldNotBeBlank()
        }
    }

    // Account ---------------------------------------------------------------------------------------------------------

    @Test
    fun accountWallets() {
        runBlocking {

            val token = authLogin(Alice)?.token
            WalletManager.token shouldBe token

            val res: WalletsResponse = WalletManager.accountWallets()
            res.account.shouldNotBeBlank()
            res.wallets.shouldNotBeEmpty()
        }
    }

    // Keys ------------------------------------------------------------------------------------------------------------

    @Test
    fun keys() {
        runBlocking {
            authLogin(Alice)
            val wid = walletId().shouldNotBeNull()
            val res: Array<KeyResponse> = WalletManager.keys(wid)
            res.shouldNotBeEmpty()
        }
    }

    // DIDs ------------------------------------------------------------------------------------------------------------

    @Test
    fun dids() {
        runBlocking {
            authLogin(Alice)
            val wid = walletId().shouldNotBeNull()
            val res: Array<DIDResponse> = WalletManager.dids(wid)
            res.shouldNotBeEmpty()
        }
    }

    @Test
    fun didsCreateKey() {
        runBlocking {
            authLogin(Alice)
            val wid = walletId().shouldNotBeNull()
            val keys = walletKeys(wid)
            val alias = "did:key#${keys.size + 1}"
            val req = DIDCreateKeyRequest(wid, alias)
            val did: String = WalletManager.didsCreateKey(req)
            did.shouldNotBeBlank()
        }
    }

    @Test
    fun userLogout() {
        runBlocking {
            val res = WalletManager.authLogout()
            res shouldBe true
        }
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private suspend fun authLogin(user: User): AuthLoginResponse? {
        val res = WalletManager.authLogin(
            AuthLoginRequest(
                type = "email",
                email = user.email,
                password = user.password
            )
        )
        return res
    }

    private suspend fun walletId(): String? {
        require(WalletManager.token != null) { "Login required" }
        val res = WalletManager.accountWallets()
        return res.wallets.singleOrNull()?.id
    }

    private suspend fun walletKeys(wid: String): List<String> {
        return WalletManager.keys(wid).map { kr -> kr.keyId.id }
    }
}
