package org.nessus.didcomm.client

import io.ktor.client.*
import io.ktor.client.call.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.*
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.http.HttpHeaders.Authorization
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.isActive
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json

// Authentication --------------------------------------------------------------------------------------------------

@Serializable
data class AuthLoginRequest(
    val type: String,
    val email: String,
    val password: String
)

@Serializable
data class AuthLoginResponse(
    val id: String,
    val username: String,
    val token: String
)

@Serializable
data class AuthRegisterRequest(
    val type: String,
    val name: String,
    val email: String,
    val password: String
)

// Account ---------------------------------------------------------------------------------------------------------

@Serializable
data class Wallet(
    val id: String,
    val name: String,
    val createdOn: String,
    val addedOn: String,
    val permission: String
)

@Serializable
@Suppress("ArrayInDataClass")
data class WalletsResponse(
    val account: String,
    val wallets: Array<Wallet>
)

// Keys ----------------------------------------------------------------------------------------------------------------

@Serializable
data class KeyResponse(
    val algorithm: String,
    val cryptoProvider: String,
    val keyId: KeyId,
)

@Serializable
data class KeyId(
    val id: String,
)

// Keys ----------------------------------------------------------------------------------------------------------------

@Serializable
data class DIDResponse(
    val did: String,
    val alias: String,
    val document: String,
    val keyId: String,
    val createdOn: String,
    val default: Boolean
)

@Serializable
data class DIDCreateKeyRequest(
    val wallet: String,
    val alias: String = "",
    val keyId: String = "",
    val useJwkJcsPub: Boolean = false,
)

@Serializable
data class ErrorResponse(
    val exception: Boolean,
    val id: String,
    val status: String,
    val code: Int,
    val message: String,
)

class APIException(val code: Int, status: String, message: String): RuntimeException(message) {
    constructor(err: ErrorResponse) : this (err.code, err.status, err.message)
}

// WalletManager =======================================================================================================

object WalletManager {

    val baseUrl: String = "http://localhost:32001"
    var client: HttpClient? = null
    var token: String? = null

    // Authentication --------------------------------------------------------------------------------------------------

    suspend fun authLogin(req: AuthLoginRequest): AuthLoginResponse {
        val res = client().post("$baseUrl/wallet-api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(req)
        }
        val decoded = handleResponse<AuthLoginResponse>(res)
        token = decoded.token
        return decoded
    }

    suspend fun authLogout(): Boolean {
        token = null
        val res = client().post("$baseUrl/wallet-api/auth/logout") {
            contentType(ContentType.Application.Json)
        }
        handleResponse<HttpResponse>(res)
        return true
    }

    suspend fun authRegister(req: AuthRegisterRequest): String {
        val res = client().post("$baseUrl/wallet-api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(req)
        }
        return handleResponse<String>(res)
    }

    // Account ---------------------------------------------------------------------------------------------------------

    suspend fun accountWallets(): WalletsResponse {
        val res = client().get("$baseUrl/wallet-api/wallet/accounts/wallets") {
            contentType(ContentType.Application.Json)
            headers {
                if (!token.isNullOrBlank()) {
                    append(Authorization, "Bearer $token")
                }
            }
        }
        return handleResponse<WalletsResponse>(res)
    }

    // Keys ------------------------------------------------------------------------------------------------------------

    suspend fun keys(walletId: String): Array<KeyResponse> {
        val res = client().get("$baseUrl/wallet-api/wallet/${walletId}/keys") {
            contentType(ContentType.Application.Json)
            headers {
                if (!token.isNullOrBlank()) {
                    append(Authorization, "Bearer $token")
                }
            }
        }
        return handleResponse<Array<KeyResponse>>(res)
    }

    // DIDs ------------------------------------------------------------------------------------------------------------

    suspend fun dids(walletId: String): Array<DIDResponse> {
        val res = client().get("$baseUrl/wallet-api/wallet/${walletId}/dids") {
            contentType(ContentType.Application.Json)
            headers {
                if (!token.isNullOrBlank()) {
                    append(Authorization, "Bearer $token")
                }
            }
        }
        return handleResponse<Array<DIDResponse>>(res)
    }

    suspend fun didsCreateKey(req: DIDCreateKeyRequest): String {
        val res = client().post("$baseUrl/wallet-api/wallet/${req.wallet}/dids/create/key") {
            contentType(ContentType.Application.Json)
            headers {
                if (!token.isNullOrBlank()) {
                    append(Authorization, "Bearer $token")
                }
            }
            url {
                if (req.keyId.isNotEmpty()) {
                    parameters.append("keyId", req.keyId)
                }
                if (req.alias.isNotEmpty()) {
                    parameters.append("alias", req.alias)
                }
                parameters.append("useJwkJcsPub", "${req.useJwkJcsPub}")
            }
        }
        return handleResponse(res)
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun client(): HttpClient {
        if (client == null || !client!!.isActive) {
            client = HttpClient(CIO) {
                install(ContentNegotiation) {
                    json()
                }
            }
        }
        return client!!
    }

    private suspend inline fun <reified T> handleResponse(res: HttpResponse): T {
        val body = res.bodyAsText()
        val json = Json { ignoreUnknownKeys = true }
        if (200 <= res.status.value && res.status.value < 300) {
            return if (T::class == HttpResponse::class) {
                @Suppress("UNCHECKED_CAST")
                res as T
            } else if (T::class == String::class) {
                @Suppress("UNCHECKED_CAST")
                body as T
            } else {
                json.decodeFromString<T>(body)
            }
        }
        val err = json.decodeFromString<ErrorResponse>(body)
        throw APIException(err)
    }
}
