package org.nessus.identity.proxy

import id.walt.oid4vc.responses.TokenResponse
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.install
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonNull.content
import org.nessus.identity.proxy.ConfigProvider.config
import org.nessus.identity.proxy.ConfigProvider.mainConfig
import org.nessus.identity.proxy.HttpProvider.http
import java.io.File
import java.net.URI
import java.net.URLDecoder
import java.security.KeyStore

fun main() {
    EBSIConformanceProxy().runServer()
}

class HttpStatusException(val status: HttpStatusCode, override val message: String) : RuntimeException(message) {
    override fun toString(): String {
        val s = "${javaClass.getName()}[code=$status]"
        return if (message.isNotBlank()) "$s: $message" else s
    }
}

class EBSIConformanceProxy {

    companion object {
        val log = KotlinLogging.logger {}
    }

    constructor() {
        log.info { "Starting OID4VC Server ..." }
        log.info { "BaseUrl: ${config.baseUrl}" }
    }

    fun runServer() {

        val host = mainConfig.getString("server.host")
        val port = mainConfig.getInt("server.port")

        val tlsEnabled = mainConfig.getBoolean("tls.enabled")

        embeddedServer(Netty, configure = {
            if (tlsEnabled) {
                val keyAlias = mainConfig.getString("tls.key_alias")
                val keystoreFile = mainConfig.getString("tls.keystore_file")
                val keystorePassword = mainConfig.getString("tls.keystore_password").toCharArray()
                val keyStore = KeyStore.getInstance("PKCS12").apply {
                    load(File(keystoreFile).inputStream(), keystorePassword)
                }
                sslConnector(
                    keyStore, keyAlias,
                    { keystorePassword }, // Must both match -passout
                    { keystorePassword }
                ) {
                    this.port = port
                    this.host = host
                }
            } else {
                connector {
                    this.port = port
                    this.host = host
                }
            }
        }) {
            install(ContentNegotiation) {
                json()
            }
            install(StatusPages) {
                exception<HttpStatusException> { call, ex ->
                    log.error(ex) { "Unexpected response status: ${ex.status} ${ex.message}" }
                    call.respond(ex.status, ex.message)
                }
                exception<Throwable> { call, ex ->
                    log.error(ex) { "Unhandled exception" }
                    call.respond(HttpStatusCode.InternalServerError, ex.message ?: "Internal error")
                }
            }
            routing {
                get("/.well-known/openid-credential-issuer") {
                    log.info { call.request.uri }
                    handleOID4VCIssuerMetadata(call)
                }
                get("/auth-callback") {
                    handleAuthCallback(call)
                }
                get("/openid-credential-offer") {
                    handleReceiveCredentialOffer(call)
                }
                get("{...}") {
                    log.info { call.request.uri }
                    handleHome(call)
                }
            }
        }.start(wait = true)
    }

    suspend fun handleAuthCallback(call: RoutingCall) {
        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented"
        )
    }

    suspend fun handleOID4VCIssuerMetadata(call: RoutingCall) {
        val payload = Json.encodeToString(NessusOpenID4VCI.issuerMetadata)
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    suspend fun handleHome(call: RoutingCall) {
        val content = javaClass.getResource("/static/index.html")?.readText()
            ?: error("Cannot find load index.html")
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Text.Html,
            text = content
        )
    }

    // Request and present Verifiable Credentials
    // https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows
    suspend fun handleReceiveCredentialOffer(call: RoutingCall) {

        // Get Credential Offer URI from the query Parameters
        //
        val credOfferUri = call.request.queryParameters["credential_offer_uri"]
            ?: throw HttpStatusException(HttpStatusCode.BadRequest, "No 'credential_offer_uri' param")

        // Parse and resolve the CredentialOfferUri into a CredentialOffer
        //
        val credOffer = NessusOpenID4VC.receiveCredentialOfferUri(credOfferUri)

        // Process the CredentialOffer and create a CredentialOfferContext
        //
        val ctx = NessusOpenID4VC.receiveCredentialOffer(credOffer)

        // Further work could happen async -------------------------------------------

        val authCode = NessusOpenID4VC.sendAuthorizationRequest(ctx)
        val tokenResponse = NessusOpenID4VC.sendTokenRequest(ctx, authCode)
        val credJwt = NessusOpenID4VC.sendCredentialRequest(ctx, tokenResponse)

        // Respond to the caller with 202 Accepted
        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Application.Json,
            text = "${credJwt.jwtClaimsSet}"
        )
    }
}

fun urlQueryToMap(url: String): Map<String, String> {
    return URI(url).rawQuery?.split("&")?.associate { p ->
        p.split("=", limit = 2).let { (k, v) -> k to URLDecoder.decode(v, "UTF-8") }
    } ?: mapOf()
}
