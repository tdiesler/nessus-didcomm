package io.nessus.identity.service


import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import io.kotest.matchers.booleans.shouldBeFalse
import io.kotest.matchers.collections.shouldNotBeEmpty
import io.kotest.matchers.nulls.shouldBeNull
import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldNotBeBlank
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import org.junit.jupiter.api.Test

class WalletServiceTest {

    val walletService = WalletService.build()

    // Authentication --------------------------------------------------------------------------------------------------

    @Test
    fun registerUser() {
        runBlocking {

            // Check whether Alice already exists
            //
            var ctx: LoginContext? = null
            try {
                ctx = walletService.login(Alice.toLoginParams())
            } catch (ex: Exception) {
                if (ex.message?.contains("Unknown user") == false) {
                    throw ex
                }
            }

            if (ctx == null) {
                val success = walletService.registerUser(Alice.toRegisterUserParams())
                success shouldBe "Registration succeeded"
            }
        }
    }

    @Test
    fun userLogin() {
        runBlocking {
            val ctx = walletService.login(Alice.toLoginParams())
            ctx.authToken.shouldNotBeBlank()
            ctx.hasWalletInfo.shouldBeFalse()
        }
    }

    // Account ---------------------------------------------------------------------------------------------------------

    @Test
    fun listWallets() {
        runBlocking {
            authLogin(Alice)
            val wallets = walletService.listWallets()
            wallets.shouldNotBeEmpty()
        }
    }

    // Keys ------------------------------------------------------------------------------------------------------------

    @Test
    fun listKeys() {
        runBlocking {
            authLoginWithWallet(Alice)
            val keys = walletService.listKeys()
            keys.shouldNotBeEmpty()
        }
    }

    @Test
    fun createKey() {
        runBlocking {
            authLoginWithWallet(Alice)
            val key = walletService.createKey(KeyType.SECP256R1)
            key.algorithm shouldBe KeyType.SECP256R1.algorithm
        }
    }

    // DIDs ------------------------------------------------------------------------------------------------------------

    @Test
    fun listDids() {
        runBlocking {
            authLoginWithWallet(Alice)
            val res: Array<DidInfo> = walletService.listDids()
            res.shouldNotBeEmpty()
        }
    }

    @Test
    fun createDidKey() {
        runBlocking {
            authLoginWithWallet(Alice)
            val keys = walletService.listKeys()
            val alias = "did:key#${keys.size + 1}"
            walletService.findDidByPrefix("did:key")?: runBlocking {
                val key = walletService.findKeyByType(KeyType.SECP256R1)
                val didInfo = walletService.createDidKey(alias, key?.id ?: "")
                didInfo.did.shouldNotBeBlank()
            }
        }
    }

    @Test
    fun signVerifyWithDid() {
        runBlocking {
            authLoginWithWallet(Alice)
            val did = walletService.findDidByPrefix("did:key").shouldNotBeNull()
            val signJwt = walletService.signWithDid(did.did, "Kermit")
            signJwt.shouldNotBeBlank()

            val docJson = Json.parseToJsonElement(did.document).jsonObject
            val verificationMethods = docJson["verificationMethod"] as JsonArray
            val verificationMethod = verificationMethods.let { it[0] as JsonObject }
            val publicKeyJwk = Json.encodeToString(verificationMethod["publicKeyJwk"])

            val publicJwk = ECKey.parse(publicKeyJwk)
            val verifier = ECDSAVerifier(publicJwk)

            // JWT-style split
            val parts = signJwt.split('.')
            parts.size shouldBe 3

            val header = JWSHeader.parse(Base64URL.from(parts[0]))
            val signature = Base64URL.from(parts[2])

            val signedContent = "${parts[0]}.${parts[1]}"
            val success = verifier.verify(header, signedContent.toByteArray(), signature)
            success shouldBe true
        }
    }

    // Logout ----------------------------------------------------------------------------------------------------------

    @Test
    fun userLogout() {
        runBlocking {
            walletService.logout()
        }
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private suspend fun authLogin(user: User): LoginContext {
        if (!walletService.hasLoginContext()) {
            walletService.login(user.toLoginParams())
        }
        return walletService.getLoginContext()
    }

    private suspend fun authLoginWithWallet (user: User): LoginContext {
        val ctx = authLogin(user)
        if (!ctx.hasWalletInfo) {
            ctx.walletInfo = walletService.listWallets().first()
        }
        return ctx
    }
}