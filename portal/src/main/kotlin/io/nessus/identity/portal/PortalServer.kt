package io.nessus.identity.portal

import io.github.oshai.kotlinlogging.KotlinLogging
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
import io.nessus.identity.service.ConfigProvider
import io.nessus.identity.service.DidInfo
import io.nessus.identity.service.LoginParams
import io.nessus.identity.service.LoginType
import io.nessus.identity.service.ServiceManager.walletService
import io.nessus.identity.service.WalletInfo
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.Json
import java.io.File
import java.security.KeyStore

fun main() {
    PortalServer().runServer()
}

class HttpStatusException(val status: HttpStatusCode, override val message: String) : RuntimeException(message) {
    override fun toString(): String {
        val s = "${javaClass.getName()}[code=$status]"
        return if (message.isNotBlank()) "$s: $message" else s
    }
}

class PortalServer {

    val log = KotlinLogging.logger {}

    val walletInfo: WalletInfo
    val didInfo: DidInfo

    constructor() {
        log.info { "Starting Nessus Portal Server ..." }
        val holderConfig = ConfigProvider.requireHolderConfig()
        walletInfo = runBlocking {
            walletService.loginWallet(
                LoginParams(
                    LoginType.EMAIL,
                    holderConfig.userEmail,
                    holderConfig.userPassword
                )
            )
        }
        didInfo = runBlocking {
            walletService.findDidByPrefix(walletInfo.id, "did:key")
                ?: throw IllegalStateException("No did:key in wallet: ${walletInfo.id}")
        }

        log.info { "Wallet: ${walletInfo.id}" }
        log.info { "Did: ${didInfo.did}" }
    }

    fun runServer() {

        embeddedServer(Netty, configure = {
            val srv = ConfigProvider.requireServerConfig()
            ConfigProvider.root.tls?.also { tls ->
                if (tls.enabled) {
                    val keystorePassword = tls.keystorePassword.toCharArray()
                    val keyStore = KeyStore.getInstance("PKCS12").apply {
                        load(File(tls.keystoreFile).inputStream(), keystorePassword)
                    }
                    sslConnector(
                        keyStore, tls.keyAlias,
                        { keystorePassword }, // Must both match -passout
                        { keystorePassword }
                    ) {
                        this.host = srv.host
                        this.port = srv.port
                    }
                }
            } ?: run {
                connector {
                    this.host = srv.host
                    this.port = srv.port
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
                route("/oauth{...}") {
                    handle { handleOAuthRequests(call) }
                }
                route("/holder{...}") {
                    handle { handleHolderRequests(call) }
                }
                route("/issuer{...}") {
                    handle { handleIssuerRequests(call) }
                }
                route("/") {
                    get {
                        log.info { call.request.uri }
                        handleHome(call)
                    }
                }
            }
        }.start(wait = true)
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

    // Handle requests to the Authentication Server
    //
    suspend fun handleOAuthRequests(call: RoutingCall) {

        val reqUri = call.request.uri
        log.info { "OAuth Request $reqUri" }
        val queryParams = urlQueryToMap(reqUri).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        if (call.request.path().endsWith(".well-known/openid-configuration")) {
            return handleAuthorizationMetadata(call)
        }

        // Callback as part of the Authorization Request
        if (queryParams["response_type"] == "id_token") {
            return handleResponseToAuthorizationRequest(call)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented $reqUri"
        )
    }

    // Handle requests to the holder wallet
    //
    suspend fun handleHolderRequests(call: RoutingCall) {

        val reqUri = call.request.uri
        log.info { "Holder Request $reqUri" }
        val queryParams = urlQueryToMap(reqUri).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        // Handle CredentialOffer by URI
        //
        if (queryParams["credential_offer_uri"] != null) {
            return handleCredentialOffer(call)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented $reqUri"
        )
    }

    // Handle requests to the holder wallet
    //
    suspend fun handleIssuerRequests(call: RoutingCall) {

        val reqUri = call.request.uri
        log.info { "Issuer Request $reqUri" }
        urlQueryToMap(reqUri).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        if (call.request.path().endsWith(".well-known/openid-credential-issuer")) {
            return handleIssuerMetadata(call)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented $reqUri"
        )
    }

    // OAuth -----------------------------------------------------------------------------------------------------------

    private suspend fun handleAuthorizationMetadata(call: RoutingCall) {

        val payload = Json.encodeToString(OAuthActions.oauthMetadata)
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload)
    }

    private suspend fun handleResponseToAuthorizationRequest(call: RoutingCall) {

        val queryParams = urlQueryToMap(call.request.uri)
        OAuthActions.handleIDTokenExchange(queryParams)

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Text.Plain,
            text = "Accepted"
        )
    }

    // Holder ----------------------------------------------------------------------------------------------------------

    // Request and present Verifiable Credentials
    // https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows
    //
    // Issuer initiated flows start with the Credential Offering proposed by Issuer.
    // The Credential Offering is in redirect for same-device tests and in QR Code for cross-device tests.
    //
    private suspend fun handleCredentialOffer(call: RoutingCall) {

        // Get Credential Offer URI from the query Parameters
        //
        val credOfferUri = call.request.queryParameters["credential_offer_uri"]
            ?: throw HttpStatusException(HttpStatusCode.BadRequest, "No 'credential_offer_uri' param")

        val oid4vcOfferUri = "openid-credential-offer://?credential_offer_uri=$credOfferUri"
        val credOffer = HolderActions.fetchCredentialOfferFromUri(oid4vcOfferUri)

        val ctx = CredentialOfferContext().also {
            it.walletInfo = walletInfo
            it.didInfo = didInfo
        }.also {
            SimpleSession.putCredentialOfferContext(it)
        }

        val authRequest = HolderActions.authorizationRequestFromCredentialOffer(ctx, credOffer)
        val authCode = HolderActions.sendAuthorizationRequest(ctx, authRequest)
        val tokenResponse = OAuthActions.sendTokenRequest(ctx, authCode)
        val credJwt = HolderActions.sendCredentialRequest(ctx, tokenResponse)
        HolderActions.addCredentialToWallet(ctx, credJwt)

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Application.Json,
            text = "${credJwt.jwtClaimsSet}"
        )
    }

    // Issuer ----------------------------------------------------------------------------------------------------------

    private suspend fun handleIssuerMetadata(call: RoutingCall) {

        val payload = Json.encodeToString(IssuerActions.issuerMetadata)
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload)
    }
}
