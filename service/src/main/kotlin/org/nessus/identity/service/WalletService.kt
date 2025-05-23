package org.nessus.identity.service

import io.github.oshai.kotlinlogging.KotlinLogging
import java.lang.IllegalStateException

class WalletService {

    val api : WalletApiClient
    val authToken get() = { api.authToken() }

    companion object {
        val log = KotlinLogging.logger {}
        fun build(walletApiUrl: String = "http://localhost:9090") : WalletService {
            return WalletService(walletApiUrl)
        }
    }

    constructor(walletApiUrl: String) {
        log.info { "WalletService: $walletApiUrl" }
        api = WalletApiClient(walletApiUrl)
    }

    // Authentication --------------------------------------------------------------------------------------------------

    suspend fun registerUser(params: RegisterUserParams): String {
        return api.authRegister(params.toAuthRegisterRequest()).trim()
    }

    suspend fun login(params: LoginParams): String {
        val res = api.authLogin(params.toAuthLoginRequest())
        return res.token
    }

    suspend fun loginWallet(params: LoginParams): WalletInfo {
        api.authLogin(params.toAuthLoginRequest())
        return api.accountWallets().wallets.first()
    }

    suspend fun logout(): Boolean {
        return api.authLogout()
    }

    // Account ---------------------------------------------------------------------------------------------------------

    suspend fun findWallet(predicate: suspend (WalletInfo) -> Boolean): WalletInfo? {
        return api.accountWallets().wallets.firstOrNull { predicate(it) }
    }

    suspend fun findWalletByDid(did: String): WalletInfo? {
        return findWallet { w -> listDids(w.id).any { it.did == did } }
    }

    suspend fun findWalletById(id: String): WalletInfo? {
        return findWallet { w -> w.id == id }
    }

    suspend fun listWallets(): Array<WalletInfo> {
        val res = api.accountWallets()
        return res.wallets
    }

    // Keys ------------------------------------------------------------------------------------------------------------

    suspend fun findKey(walletId: String, predicate: suspend (Key) -> Boolean): Key? {
        return listKeys(walletId).firstOrNull { predicate(it) }
    }

    suspend fun findKeyByAlgorithm(walletId: String, algorithm: String): Key? {
        return findKey(walletId) { k -> k.algorithm.equals(algorithm, ignoreCase = true) }
    }

    suspend fun findKeyById(walletId: String, keyId: String): Key? {
        return findKey(walletId) { k -> k.id == keyId }
    }

    suspend fun findKeyByType(walletId: String, keyType: KeyType): Key? {
        return findKeyByAlgorithm(walletId, keyType.algorithm)
    }

    suspend fun listKeys(walletId: String): Array<Key> {
        val res: Array<KeyResponse> = api.keys(walletId)
        return res.map { kr -> Key(kr.keyId.id, kr.algorithm) }.toTypedArray()
    }

    suspend fun createKey(walletId: String, keyType: KeyType): Key {
        val kid = api.keysGenerate(walletId, keyType)
        return findKeyById(walletId, kid)!!
    }

    suspend fun signWithDid(walletId: String, did: String, message: String): String {
        val keyId = findDid(walletId) { d -> d.did == did }?.keyId
            ?: throw IllegalStateException("No such did: $did")
        return signWithKey(walletId, keyId, message)
    }

    suspend fun signWithKey(walletId: String, alias: String, message: String): String {
        return api.keysSign(walletId, alias, message)
    }

    // DIDs ------------------------------------------------------------------------------------------------------------

    suspend fun findDid(walletId: String, predicate: suspend (DidInfo) -> Boolean): DidInfo? {
        return listDids(walletId).firstOrNull { predicate(it) }
    }

    suspend fun findDidByPrefix(walletId: String, prefix: String): DidInfo? {
        return findDid(walletId) { d -> d.did.startsWith(prefix) }
    }

    suspend fun getDefaultDid(walletId: String): DidInfo {
        return findDid(walletId) { d -> d.default}
            ?: throw IllegalStateException("No default did for: $walletId")
    }

    suspend fun getDidDocument(walletId: String, did: String): String {
        val didInfo = api.did(walletId, did)
        return didInfo
    }

    suspend fun listDids(walletId: String): Array<DidInfo> {
        val dids: Array<DidInfo> = api.dids(walletId)
        return dids
    }

    suspend fun createDidKey(walletId: String, alias: String, keyId: String): DidInfo {
        val req = CreateDidKeyRequest(walletId, alias, keyId)
        val did: String = api.didsCreateDidKey(req)
        val didInfo = api.dids(walletId).first { di -> di.did == did }
        return didInfo
    }
}
