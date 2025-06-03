package io.nessus.identity.portal

import com.nimbusds.jwt.SignedJWT
import freemarker.cache.ClassTemplateLoader
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.requests.CredentialRequest
import id.walt.webwallet.db.models.WalletCredentialCategoryMap.credential
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.install
import io.ktor.server.engine.*
import io.ktor.server.freemarker.FreeMarker
import io.ktor.server.freemarker.FreeMarkerContent
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.plugins.statuspages.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import io.ktor.server.sessions.Sessions
import io.ktor.server.sessions.cookie
import io.ktor.server.sessions.sessions
import io.ktor.util.toMap
import io.nessus.identity.portal.CredentialExchange.Companion.requireCredentialExchange
import io.nessus.identity.service.ConfigProvider
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.LoginParams
import io.nessus.identity.service.LoginType
import io.nessus.identity.service.ServiceProvider.walletService
import io.nessus.identity.service.publicKeyJwk
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import java.io.File
import java.security.KeyStore
import kotlin.collections.component1
import kotlin.collections.component2

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

    constructor() {
        log.info { "Starting Nessus Portal Server ..." }
        val serverConfig = ConfigProvider.requireServerConfig()
        val serviceConfig = ConfigProvider.requireServiceConfig()
        val databaseConfig = ConfigProvider.requireDatabaseConfig()
        log.info { "ServerConfig: ${Json.encodeToString(serverConfig)}" }
        log.info { "ServiceConfig: ${Json.encodeToString(serviceConfig)}" }
        log.info { "DatabaseConfig: ${Json.encodeToString(databaseConfig)}" }
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
            install(FreeMarker) {
                templateLoader = ClassTemplateLoader(this::class.java.classLoader, "templates")
            }
            install(Sessions) {
                cookie<CookieData>(CookieData.NAME) {
                    cookie.path = "/"
                    cookie.maxAgeInSeconds = 3600
                }
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
                get("/") {
                    handleHome(call)
                }
                post("/login") {
                    handleLogin(call)
                    call.respondRedirect("/")
                }
                get("/logout") {
                    getLoginContextFromSession(call)?.also { it.close() }
                    call.sessions.clear(CookieData.NAME)
                    call.respondRedirect("/")
                }
                route("/auth/{subId}/{...}") {
                    handle {
                        val subId = call.parameters["subId"] ?: throw IllegalArgumentException("No subId")
                        handleAuthRequests(call, subId)
                    }
                }
                route("/wallet/{subId}/{...}") {
                    handle {
                        val subId = call.parameters["subId"] ?: throw IllegalArgumentException("No subId")
                        handleWalletRequests(call, subId)
                    }
                }
                route("/issuer/{subId}/{...}") {
                    handle {
                        val subId = call.parameters["subId"] ?: throw IllegalArgumentException("No subId")
                        handleIssuerRequests(call, subId)
                    }
                }
            }
        }.start(wait = true)
    }

    suspend fun handleHome(call: RoutingCall) {
        val serviceConfig = ConfigProvider.requireServiceConfig()
        val ctx = getLoginContextFromSession(call)
        val model = mutableMapOf(
            "hasWalletId" to (ctx?.maybeWalletInfo?.name?.isNotBlank() ?: false),
            "walletName" to ctx?.maybeWalletInfo?.name,
            "did" to ctx?.maybeDidInfo?.did,
            "demoWalletUrl" to serviceConfig.demoWalletUrl,
            "devWalletUrl" to serviceConfig.devWalletUrl,
        )
        if (ctx?.hasDidInfo == true) {
            model["subjectId"] = ctx.subjectId
            model["walletUri"] = "${ConfigProvider.walletEndpointUri}/${ctx.subjectId}"
            model["issuerUri"] = "${ConfigProvider.issuerEndpointUri}/${ctx.subjectId}"
        }
        call.respond(
            FreeMarkerContent(
                template = "index.ftl",
                model = model
            )
        )
    }

    // Handle Login ----------------------------------------------------------------------------------------------------
    //
    suspend fun handleLogin(call: RoutingCall) {

        val params = call.receiveParameters()
        val email = params["email"]
        val password = params["password"]

        if (email.isNullOrBlank() || password.isNullOrBlank())
            return call.respond(HttpStatusCode.BadRequest, "Missing email or password")

        runBlocking {
            walletService.loginWallet(LoginParams(LoginType.EMAIL, email, password))
            val ctx = walletService.getLoginContext()
            walletService.findDidByPrefix("did:key")?.also {
                ctx.didInfo = it
            }
            val dat = CookieData(ctx.walletInfo.id, ctx.maybeDidInfo?.did)
            setCookieDataInSession(call, dat)
        }
    }

    // Handle Authorization requests -----------------------------------------------------------------------------------
    //
    suspend fun handleAuthRequests(call: RoutingCall, subId: String) {

        val reqUri = call.request.uri
        val path = call.request.path()

        log.info { "Auth Request $reqUri" }
        val queryParams = urlQueryToMap(reqUri).also {
            it.forEach { (k, v) ->
                log.info { "  $k=$v" }
            }
        }

        val ctx = requireLoginContext(subId)

        if (path.endsWith(".well-known/openid-configuration")) {
            return handleAuthorizationMetadataRequest(call, ctx)
        }

        // authorize
        // 
        if (path == "/auth/$subId/authorize") {
            val cex = CredentialExchange(ctx)
            return handleAuthorizationRequest(call, cex)
        }

        // direct_post
        //
        if (path == "/auth/$subId/direct_post") {
            val cex = requireCredentialExchange(ctx.subjectId)
            return handleAuthDirectPost(call, cex)
        }

        // jwks
        //
        if (path == "/auth/$subId/jwks") {
            return handleAuthJwksRequest(call, ctx)
        }

        // token
        //
        if (path == "/auth/$subId/token") {
            val cex = requireCredentialExchange(ctx.subjectId)
            return handleAuthTokenRequest(call, cex)
        }

        // Callback as part of the Authorization Request
        // [TODO] Review whether we really want to redirect here
        if (path == "/auth/$subId" && queryParams["response_type"] == "id_token") {
            val cex = requireCredentialExchange(ctx.subjectId)
            return handleResponseToAuthorizationRequest(call, cex)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented $reqUri"
        )
    }

    // Handle Wallet requests ------------------------------------------------------------------------------------------
    //
    suspend fun handleWalletRequests(call: RoutingCall, subId: String) {

        val reqUri = call.request.uri
        val path = call.request.path()

        log.info { "Wallet Request $reqUri" }
        val queryParams = urlQueryToMap(reqUri).also {
            it.forEach { (k, v) ->
                log.info { "  $k=$v" }
            }
        }

        val ctx = requireLoginContext(subId)
        val cex = CredentialExchange(ctx)

        // Handle CredentialOffer by Uri
        //
        if (path == "/wallet/$subId" && queryParams["credential_offer_uri"] != null) {
            return handleCredentialOffer(call, cex)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented $reqUri"
        )
    }

    // Handle Issuer requests ------------------------------------------------------------------------------------------
    //
    suspend fun handleIssuerRequests(call: RoutingCall, subId: String) {

        val reqUri = call.request.uri
        val path = call.request.path()

        log.info { "Issuer Request $reqUri" }
        urlQueryToMap(reqUri).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        val ctx = requireLoginContext(subId)

        if (call.request.path().endsWith(".well-known/openid-credential-issuer")) {
            return handleIssuerMetadataRequest(call, ctx)
        }

        // Handle Credential Request
        //
        if (path == "/issuer/$subId/credential") {
            val cex = requireCredentialExchange(subId)
            return handleCredentialRequest(call, cex)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented $reqUri"
        )
    }

    // LoginContext ----------------------------------------------------------------------------------------------------

    private suspend fun requireLoginContext(subId: String): LoginContext {

        // We expect the user to have logged in previously and have a valid Did
        //
        var ctx = LoginContext.findLoginContext(subId)

        // Fallback
        if (ctx == null) {
            val cfg = ConfigProvider.requireWalletConfig()
            if (cfg.userEmail.isNotBlank() && cfg.userPassword.isNotBlank()) {
                val loginParams = LoginParams(LoginType.EMAIL, cfg.userEmail, cfg.userPassword)
                walletService.loginWallet(loginParams)
                ctx = walletService.getLoginContext()
            }
        }

        ctx ?: throw IllegalStateException("Login required")

        if (ctx.maybeDidInfo == null) {
            ctx.didInfo = walletService.findDidByPrefix("did:key")
                ?: throw IllegalStateException("Cannot find required did in wallet")
        }

        return ctx
    }

    // Authorization ---------------------------------------------------------------------------------------------------

    private suspend fun handleAuthorizationMetadataRequest(call: RoutingCall, ctx: LoginContext) {

        val payload = Json.encodeToString(AuthActions.getAuthMetadata(ctx))
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    /**
     * The Wallet requests access for the required credential from the Issuer's Authorisation Server.
     */
    private suspend fun handleAuthorizationRequest(call: RoutingCall, cex: CredentialExchange) {

        val queryParams = call.parameters.toMap()
        val authReq = AuthorizationRequest.fromHttpParameters(queryParams)
        log.info { "AuthRequest: ${Json.encodeToString(authReq)}" }

        val idTokenRedirectUrl = AuthActions.handleAuthorizationRequest(cex, authReq)
        call.respondRedirect(idTokenRedirectUrl)
    }

    /**
     * Client requests key details
     */
    private suspend fun handleAuthDirectPost(call: RoutingCall, cex: CredentialExchange) {

        val postParams = call.receiveParameters().toMap()
        log.info { "Auth DirectPost: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        if (postParams["id_token"] != null) {
            val idTokenResUrl = AuthActions.handleIDTokenResponse(cex, postParams)
            return call.respondRedirect(idTokenResUrl)
        }

        call.respondText(
            status = HttpStatusCode.InternalServerError,
            contentType = ContentType.Text.Plain,
            text = "Not Implemented"
        )
    }

    /**
     * Client requests key details
     */
    private suspend fun handleAuthJwksRequest(call: RoutingCall, ctx: LoginContext) {

        val keyJwk = ctx.didInfo.publicKeyJwk()
        val keys = mapOf("keys" to listOf(keyJwk))
        val payload = Json.encodeToString(keys)

        log.info { "Jwks $payload" }

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    /**
     * Client requests an Access Token
     */
    private suspend fun handleAuthTokenRequest(call: RoutingCall, cex: CredentialExchange) {

        val postParams = call.receiveParameters().toMap()
        log.info { "Auth Token Request: ${call.request.uri}" }
        postParams.forEach { (k, lst) -> lst.forEach { v -> log.info { "  $k=$v" } } }

        val tokenResponse = AuthActions.handleTokenRequest(cex, postParams)
        val tokenResponseJson = Json.encodeToString(tokenResponse)
        log.info { "TokenResponse: $tokenResponseJson" }


        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = tokenResponseJson
        )
    }

    private suspend fun handleResponseToAuthorizationRequest(call: RoutingCall, cex: CredentialExchange) {

        AuthActions.handleIDTokenExchange(cex, call.parameters.toMap())

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
    private suspend fun handleCredentialOffer(call: RoutingCall, cex: CredentialExchange) {

        // Get Credential Offer URI from the query Parameters
        //
        val credOfferUri = call.request.queryParameters["credential_offer_uri"]
            ?: throw HttpStatusException(HttpStatusCode.BadRequest, "No 'credential_offer_uri' param")

        val oid4vcOfferUri = "openid-credential-offer://?credential_offer_uri=$credOfferUri"

        val credOffer = WalletActions.fetchCredentialOfferFromUri(oid4vcOfferUri)
        val offeredCred = WalletActions.resolveOfferedCredentials(cex, credOffer)
        val authRequest = WalletActions.authorizationRequestFromCredentialOffer(cex, offeredCred)
        val authCode = WalletActions.sendAuthorizationRequest(cex, authRequest)
        val tokenResponse = AuthActions.sendTokenRequest(cex, authCode)
        val credJwt = WalletActions.sendCredentialRequest(cex, tokenResponse)
        WalletActions.addCredentialToWallet(cex, credJwt)

        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Application.Json,
            text = "${credJwt.jwtClaimsSet}"
        )
    }

    // Issuer ----------------------------------------------------------------------------------------------------------

    private suspend fun handleIssuerMetadataRequest(call: RoutingCall, ctx: LoginContext) {

        val issuerMetadata = IssuerActions.getIssuerMetadata(ctx)
        val payload = Json.encodeToString(issuerMetadata)
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    private suspend fun handleCredentialRequest(call: RoutingCall, cex: CredentialExchange) {

        val credReq = call.receive<CredentialRequest>()
        log.info { "CredentialRequest: ${Json.encodeToString(credReq)}" }

        val bearerToken = call.request.headers["Authorization"]
            ?.takeIf { it.startsWith("Bearer ", ignoreCase = true) }
            ?.removePrefix("Bearer ")
            ?.let { SignedJWT.parse(it) }
            ?: throw IllegalArgumentException("Invalid authorization header")

        cex.validateBearerToken(bearerToken)

        val credentialResponse = IssuerActions.handleCredentialRequest(cex, bearerToken, credReq)
        val payload = Json.encodeToString(credentialResponse)
        log.info { "Credential Response: $payload" }

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    // Session Data ----------------------------------------------------------------------------------------------------

    private fun getCookieDataFromSession(call: RoutingCall): CookieData? {
        val dat = call.sessions.get(CookieData.NAME)
        return dat as? CookieData
    }

    private fun setCookieDataInSession(call: RoutingCall, dat: CookieData) {
        call.sessions.set(CookieData.NAME, dat)
    }

    private fun getLoginContextFromSession(call: RoutingCall): LoginContext? {
        val dat = getCookieDataFromSession(call)
        val ctx = dat?.let { LoginContext.findLoginContext(it.wid, it.did ?: "") }
        return ctx
    }

    @Serializable
    data class CookieData(val wid: String, var did: String? = null) {
        companion object {
            const val NAME = "CookieData"
        }
    }
}

