package io.nessus.identity.proxy

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.plugins.contentnegotiation.ContentNegotiation
import io.ktor.serialization.kotlinx.json.*
import kotlinx.coroutines.isActive
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject

object HttpProvider {

    private var httpClient: HttpClient? = null

    fun http(): HttpClient {
        if (httpClient == null || !httpClient!!.isActive) {
            httpClient = HttpClient(CIO) {
                install(ContentNegotiation) {
                    json()
                }
            }
        }
        return httpClient!!
    }
}
