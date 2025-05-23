package org.nessus.identity.service


import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import io.kotest.matchers.collections.shouldNotBeEmpty
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

    val walletSvc = WalletService.build()
    var walletId: String? = null

    // Authentication --------------------------------------------------------------------------------------------------

    @Test
    fun registerUser() {
        runBlocking {

            // Check whether Alice already exists
            //
            var authToken: String? = null
            try {
                authToken = walletSvc.login(Alice.toLoginParams())
            } catch (ex: Exception) {
                if (ex.message?.contains("Unknown user") == false) {
                    throw ex
                }
            }

            if (authToken == null) {
                val success = walletSvc.registerUser(Alice.toRegisterUserParams())
                success shouldBe "Registration succeeded"
            }
        }
    }

    @Test
    fun userLogin() {
        runBlocking {
            val authToken = walletSvc.login(Alice.toLoginParams())
            authToken.shouldNotBeBlank()
        }
    }

    // Account ---------------------------------------------------------------------------------------------------------

    @Test
    fun listWallets() {
        runBlocking {
            authLogin(Alice)
            val wallets = walletSvc.listWallets()
            wallets.shouldNotBeEmpty()
        }
    }

    // Keys ------------------------------------------------------------------------------------------------------------

    @Test
    fun listKeys() {
        runBlocking {
            authLogin(Alice)
            val wid = walletId().shouldNotBeNull()
            val keys = walletSvc.listKeys(wid)
            keys.shouldNotBeEmpty()
        }
    }

    @Test
    fun createKey() {
        runBlocking {
            authLogin(Alice)
            val wid = walletId().shouldNotBeNull()
            val key = walletSvc.createKey(wid, KeyType.SECP256R1)
            key.algorithm shouldBe KeyType.SECP256R1.algorithm
        }
    }

    // DIDs ------------------------------------------------------------------------------------------------------------

    @Test
    fun listDids() {
        runBlocking {
            authLogin(Alice)
            val wid = walletId().shouldNotBeNull()
            val res: Array<DidInfo> = walletSvc.listDids(wid)
            res.shouldNotBeEmpty()
        }
    }

    @Test
    fun createDidKey() {
        runBlocking {
            authLogin(Alice)
            val wid = walletId().shouldNotBeNull()
            val keys = walletKeys(wid)
            val alias = "did:key#${keys.size + 1}"
            walletSvc.findDidByPrefix(wid, "did:key")?: runBlocking {
                val key = walletSvc.findKeyByType(wid, KeyType.SECP256R1)
                val didInfo = walletSvc.createDidKey(wid, alias, key?.id ?: "")
                didInfo.did.shouldNotBeBlank()
            }
        }
    }

    @Test
    fun signVerifyWithDid() {
        runBlocking {
            authLogin(Alice)
            val wid = walletId().shouldNotBeNull()
            val did = walletSvc.findDidByPrefix(wid, "did:key").shouldNotBeNull()
            val signJwt = walletSvc.signWithDid(wid, did.did, "Kermit")
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
            walletSvc.logout()
            walletId = null
        }
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private suspend fun authLogin(user: User): String? {
        var token = walletSvc.authToken()
        if (token == null) {
            token = walletSvc.login(user.toLoginParams())
        }
        return token
    }

    private suspend fun walletId(): String? {
        if (walletId == null) {
            val res = walletSvc.api.accountWallets()
            walletId = res.wallets.singleOrNull()?.id
        }
        return walletId
    }

    private suspend fun walletKeys(wid: String): List<String> {
        return walletSvc.api.keys(wid).map { kr -> kr.keyId.id }
    }
}