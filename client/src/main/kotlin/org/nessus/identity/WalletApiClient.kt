package org.nessus.identity

import io.ktor.client.*
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
data class LoginRequest(
    val type: String,
    val email: String,
    val password: String
)

@Serializable
data class LoginResponse(
    val id: String,
    val username: String,
    val token: String
)

@Serializable
data class RegisterUserRequest(
    val type: String,
    val name: String,
    val email: String,
    val password: String
)

// Account ---------------------------------------------------------------------------------------------------------

@Serializable
data class WalletInfo(
    val id: String,
    val name: String,
    val createdOn: String,
    val addedOn: String,
    val permission: String
)

@Serializable
@Suppress("ArrayInDataClass")
data class ListWalletsResponse(
    val account: String,
    val wallets: Array<WalletInfo>
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
data class DIDInfo(
    val did: String,
    val alias: String,
    val document: String,
    val keyId: String,
    val createdOn: String,
    val default: Boolean
)

@Serializable
data class CreateDidKeyRequest(
    val wallet: String,
    val alias: String = "",
    val keyId: String = "",
    val useJwkJcsPub: Boolean = false,
)

@Serializable
data class ErrorResponse(
    val exception: Boolean = false,
    val id: String = "",
    val status: String = "",
    val code: Int = 0,
    val message: String,
)

class APIException(val id: String, val code: Int, val status: String, message: String) : RuntimeException(message) {

    constructor(err: ErrorResponse) : this(err.id, err.code, err.status, err.message)

    override fun toString(): String {
        return if (id.isNotEmpty() || code > 0 || status.isNotEmpty()) {
            "APIException[id=$id, code=$code, status=$status] $message"
        } else {
            message!!
        }
    }
}

// WalletApiClient =====================================================================================================

class WalletApiClient {

    var baseUrl: String
    var client: HttpClient? = null

    constructor() : this("https://wallet-api.nessus-tech.io")

    constructor(baseUrl: String) {
        this.baseUrl = baseUrl
    }

    // Authentication --------------------------------------------------------------------------------------------------

    suspend fun authLogin(req: LoginRequest): LoginResponse {
        val res = client().post("$baseUrl/wallet-api/auth/login") {
            contentType(ContentType.Application.Json)
            setBody(req)
        }
        return handleResponse<LoginResponse>(res)
    }

    suspend fun authLogout(): Boolean {
        val res = client().post("$baseUrl/wallet-api/auth/logout") {
            contentType(ContentType.Application.Json)
        }
        handleResponse<HttpResponse>(res)
        return true
    }

    suspend fun authRegister(req: RegisterUserRequest): Boolean {
        val res = client().post("$baseUrl/wallet-api/auth/register") {
            contentType(ContentType.Application.Json)
            setBody(req)
        }
        val msg = handleResponse<String>(res)
        return "Registration succeeded" == msg
    }

    // Account ---------------------------------------------------------------------------------------------------------

    suspend fun accountWallets(token: String?): ListWalletsResponse {
        val res = client().get("$baseUrl/wallet-api/wallet/accounts/wallets") {
            contentType(ContentType.Application.Json)
            headers {
                if (!token.isNullOrBlank()) {
                    append(Authorization, "Bearer $token")
                }
            }
        }
        return handleResponse<ListWalletsResponse>(res)
    }

    // Keys ------------------------------------------------------------------------------------------------------------

    suspend fun keys(token: String?, walletId: String): Array<KeyResponse> {
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

    suspend fun did(token: String?, walletId: String, did: String): String {
        val res = client().get("$baseUrl/wallet-api/wallet/${walletId}/dids/${did}") {
            contentType(ContentType.Application.Json)
            headers {
                if (!token.isNullOrBlank()) {
                    append(Authorization, "Bearer $token")
                }
            }
        }
        return handleResponse<String>(res)
    }

    suspend fun dids(token: String?, walletId: String): Array<DIDInfo> {
        val res = client().get("$baseUrl/wallet-api/wallet/${walletId}/dids") {
            contentType(ContentType.Application.Json)
            headers {
                if (!token.isNullOrBlank()) {
                    append(Authorization, "Bearer $token")
                }
            }
        }
        return handleResponse<Array<DIDInfo>>(res)
    }

    suspend fun didsCreateDidKey(token: String?, req: CreateDidKeyRequest): String {
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
