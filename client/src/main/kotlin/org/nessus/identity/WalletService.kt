package org.nessus.identity

object WalletService {

    val api = WalletApiClient()

    // Authentication --------------------------------------------------------------------------------------------------

    suspend fun registerUser(params: RegisterUserParams): Boolean {
        return api.authRegister(params.toAuthRegisterRequest())
    }

    suspend fun login(params: LoginParams): String? {
        val res = api.authLogin(params.toAuthLoginRequest())
        return res.token
    }

    suspend fun logout() : Boolean {
        return  api.authLogout()
    }

    // Account ---------------------------------------------------------------------------------------------------------

    suspend fun listWallets(token : String?): Array<WalletInfo> {
        val res = api.accountWallets(token)
        return res.wallets
    }

    // Keys ------------------------------------------------------------------------------------------------------------

    suspend fun listKeys(token: String?, walletId: String): Array<Key> {
        val res: Array<KeyResponse> = api.keys(token, walletId)
        return res.map { kr -> Key(kr.keyId.id, kr.algorithm) }.toTypedArray()
    }

    // DIDs ------------------------------------------------------------------------------------------------------------

    suspend fun getDIDDocument(token: String?, walletId: String, did: String): String {
        val didInfo = api.did(token, walletId, did)
        return didInfo
    }

    suspend fun listDIDs(token: String?, walletId: String): Array<DIDInfo> {
        val dids: Array<DIDInfo> = api.dids(token, walletId)
        return dids
    }

    suspend fun createDidKey(token: String?, walletId: String, alias: String, keyId: String): DIDInfo {
        val req = CreateDidKeyRequest(walletId, alias, keyId)
        val did: String = api.didsCreateDidKey(token, req)
        val didInfo = api.dids(token, walletId).first { di -> di.did == did }
        return didInfo
    }

}