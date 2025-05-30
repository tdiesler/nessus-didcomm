package io.nessus.identity.service

import kotlin.collections.set

open class LoginContext() {

    constructor(authToken: String, walletInfo: WalletInfo, didInfo: DidInfo) : this() {
        _authToken = authToken
        _walletInfo = walletInfo
        _didInfo = didInfo
    }

    private var _authToken: String? = null
    private var _walletInfo: WalletInfo? = null
    private var _didInfo: DidInfo? = null

    val hasAuthToken get() = _authToken != null
    val hasWalletInfo get() = _walletInfo != null
    val hasDidInfo get() = _didInfo != null

    var authToken : String
        get() = _authToken ?: throw IllegalStateException("No authToken")
        set(token) {
            _authToken = token
        }

    var walletInfo : WalletInfo
        get() = _walletInfo ?: throw IllegalStateException("No walletInfo")
        set(wi) {
            _walletInfo = wi
            registry[wi.id] = this
        }

    var didInfo : DidInfo
        get() = _didInfo ?: throw IllegalStateException("No didInfo")
        set(di) {
            _didInfo = di
        }

    val walletId get() = walletInfo.id

    companion object {

        // A global registry that allows us to restore a LoginContext from walletId
        private val registry = mutableMapOf<String, LoginContext>()

        fun findLoginContextByWalletId(walletId : String) : LoginContext? {
            return registry[walletId]
        }
    }

    fun close() {
        _walletInfo?.also {
            registry.remove(it.name)
        }
        _authToken = null
        _didInfo = null
    }
}