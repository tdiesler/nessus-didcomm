package io.nessus.identity.service

import com.nimbusds.jwt.SignedJWT
import com.zaxxer.hikari.HikariConfig
import com.zaxxer.hikari.HikariDataSource
import id.walt.oid4vc.data.CredentialFormat
import id.walt.webwallet.db.models.WalletCredential
import id.walt.webwallet.service.credentials.CredentialsService
import io.github.oshai.kotlinlogging.KotlinLogging
import kotlinx.datetime.Clock
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.jetbrains.exposed.sql.Database
import javax.sql.DataSource
import kotlin.apply
import kotlin.collections.any
import kotlin.collections.first
import kotlin.collections.firstOrNull
import kotlin.collections.map
import kotlin.text.trim
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

class WalletService {

    val api : WalletApiClient
    private lateinit var ctx: LoginContext

    val dataSource: Lazy<DataSource> = lazy {
        val dbcfg = ConfigProvider.requireDatabaseConfig()
        log.info { "Database: ${dbcfg.jdbcUrl}" }
        HikariDataSource(HikariConfig().apply {
            jdbcUrl = dbcfg.jdbcUrl
            username = dbcfg.username
            password = dbcfg.password
            driverClassName = "org.postgresql.Driver"
            transactionIsolation = "TRANSACTION_SERIALIZABLE"
            maximumPoolSize = 10
            isAutoCommit = false
        })
    }

    private constructor(walletApiUrl: String) {
        log.info { "WalletService: $walletApiUrl" }
        api = WalletApiClient(walletApiUrl)
    }

    companion object {
        val log = KotlinLogging.logger {}
        fun build(walletApiUrl: String = "http://localhost:7001") : WalletService {
            return WalletService(walletApiUrl)
        }
    }

    fun hasLoginContext() : Boolean {
        return ::ctx.isInitialized
    }

    fun getLoginContext() : LoginContext {
        return ctx
    }

    // Authentication --------------------------------------------------------------------------------------------------

    suspend fun registerUser(params: RegisterUserParams): String {
        return api.authRegister(params.toAuthRegisterRequest()).trim()
    }

    suspend fun login(params: LoginParams): LoginContext {
        val res = api.authLogin(params.toAuthLoginRequest())
        ctx = LoginContext().also { it.authToken = res.token }
        return ctx
    }

    suspend fun loginWallet(params: LoginParams): WalletInfo {
        ctx = login(params)
        ctx.walletInfo = listWallets().first()
        return ctx.walletInfo
    }

    suspend fun logout(): Boolean {
        return api.authLogout()
    }

    // Account ---------------------------------------------------------------------------------------------------------

    suspend fun findWallet(predicate: suspend (WalletInfo) -> Boolean): WalletInfo? {
        return api.accountWallets(ctx).wallets.firstOrNull { predicate(it) }
    }

    suspend fun findWalletByDid(did: String): WalletInfo? {
        return findWallet { w -> listDids().any { it.did == did } }
    }

    suspend fun findWalletById(id: String): WalletInfo? {
        return findWallet { w -> w.id == id }
    }

    suspend fun listWallets(): Array<WalletInfo> {
        val res = api.accountWallets(ctx)
        return res.wallets
    }

    // Keys ------------------------------------------------------------------------------------------------------------

    suspend fun findKey(predicate: suspend (Key) -> Boolean): Key? {
        return listKeys().firstOrNull { predicate(it) }
    }

    suspend fun findKeyByAlgorithm(algorithm: String): Key? {
        return findKey { k -> k.algorithm.equals(algorithm, ignoreCase = true) }
    }

    suspend fun findKeyById(keyId: String): Key? {
        return findKey { k -> k.id == keyId }
    }

    suspend fun findKeyByType(keyType: KeyType): Key? {
        return findKeyByAlgorithm(keyType.algorithm)
    }

    suspend fun listKeys(): Array<Key> {
        val res: Array<KeyResponse> = api.keys(ctx)
        return res.map { kr -> Key(kr.keyId.id, kr.algorithm) }.toTypedArray()
    }

    suspend fun createKey(keyType: KeyType): Key {
        val kid = api.keysGenerate(ctx, keyType)
        return findKeyById(kid)!!
    }

    suspend fun signWithDid(did: String, message: String): String {
        val keyId = findDid { d -> d.did == did }?.keyId
            ?: throw IllegalStateException("No such did: $did")
        return signWithKey(keyId, message)
    }

    suspend fun signWithKey(alias: String, message: String): String {
        return api.keysSign(ctx, alias, message)
    }

    // DIDs ------------------------------------------------------------------------------------------------------------

    suspend fun findDid(predicate: suspend (DidInfo) -> Boolean): DidInfo? {
        return listDids().firstOrNull { predicate(it) }
    }

    suspend fun findDidByPrefix(prefix: String): DidInfo? {
        return findDid { d -> d.did.startsWith(prefix) }
    }

    suspend fun getDefaultDid(): DidInfo {
        return findDid { d -> d.default }
            ?: throw IllegalStateException("No default did for: $ctx.walletId")
    }

    suspend fun getDidDocument(did: String): String {
        val didInfo = api.did(ctx, did)
        return didInfo
    }

    suspend fun listDids(): Array<DidInfo> {
        val dids: Array<DidInfo> = api.dids(ctx)
        return dids
    }

    suspend fun createDidKey(alias: String, keyId: String): DidInfo {
        val req = CreateDidKeyRequest(alias, keyId)
        val did: String = api.didsCreateDidKey(ctx, req)
        val didInfo = api.dids(ctx).first { di -> di.did == did }
        return didInfo
    }

    // Credentials ------------------------------------------------------------------------------------------------------------

    @OptIn(ExperimentalUuidApi::class)
    fun addCredential(walletId: String, format: String, credJwt: SignedJWT): String {

        if (format != CredentialFormat.jwt_vc.value)
            throw IllegalStateException("Unsupported credential format: $format")

        val credId = getCredentialId(credJwt)
        val walletUid = Uuid.Companion.parse(walletId)

        val walletCredential = WalletCredential(
            wallet = Uuid.Companion.parse(walletId),
            id = credId,
            document = credJwt.serialize(),
            disclosures = null,
            addedOn = Clock.System.now(),
            deletedOn = null,
            format = CredentialFormat.jwt_vc
        )

        withConnection {
            CredentialsService().add(walletUid, walletCredential)
            log.info { "Added WalletCredential: $credId" }
        }
        return credId
    }

    private fun getCredentialId(credJwt: SignedJWT): String {
        val credClaims = Json.Default.parseToJsonElement("${credJwt.jwtClaimsSet}") as JsonObject
        val vc = credClaims["vc"] as? JsonObject ?: throw IllegalArgumentException("No 'vc' claim")
        return vc["id"]?.jsonPrimitive?.content ?: throw IllegalArgumentException("No 'vc.id' claim")
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun withConnection(block: () -> Unit) {
        if (!dataSource.isInitialized()) {
            Database.Companion.connect(dataSource.value)
        }
        block()
    }
}