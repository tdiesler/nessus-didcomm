package io.nessus.identity.portal

import freemarker.cache.ClassTemplateLoader
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
import io.nessus.identity.service.ConfigProvider
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.LoginParams
import io.nessus.identity.service.LoginType
import io.nessus.identity.service.ServiceManager.walletService
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
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

    constructor() {
        log.info { "Starting Nessus Portal Server ..." }
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
                post("/login") {
                    handleLogin(call)
                }
                get("/logout") {
                    getLoginContextFromSession(call)?.also { it.close() }
                    call.sessions.clear(CookieData.NAME)
                    handleHome(call)
                }
                route("/oauth{...}") {
                    handle { handleOAuthRequests(call) }
                }
                route("/holder/{walletId}") {
                    handle {
                        val walletId = call.parameters["walletId"] ?: throw IllegalArgumentException("No walletId")
                        handleHolderRequests(call, walletId)
                    }
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
        val serviceConfig = ConfigProvider.requireServiceConfig()
        val ctx = getLoginContextFromSession(call)
        val walletId = ctx?.walletInfo?.id
        val holderBaseUri = ConfigProvider.holderEndpointUri
        call.respond(
            FreeMarkerContent(
                template = "index.ftl",
                model = mapOf(
                    "walletName" to ctx?.walletInfo?.name,
                    "did" to ctx?.didInfo?.did,
                    "holderUri" to "$holderBaseUri/$walletId",
                    "demoWalletUrl" to serviceConfig.demoWalletUrl
                )
            )
        )
    }

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
            val dat = CookieData(ctx.walletInfo.id, ctx.didInfo.did)
            setCookieDataInSession(call, dat)
        }

        call.respondRedirect("/")
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
    suspend fun handleHolderRequests(call: RoutingCall, walletId: String) {

        val reqUri = call.request.uri
        log.info { "Holder Request $reqUri" }
        val queryParams = urlQueryToMap(reqUri).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        val lctx = resolveLoginContext(walletId)
        val hctx = HolderContext(lctx)

        // Handle CredentialOffer by URI
        //
        if (queryParams["credential_offer_uri"] != null) {
            return handleCredentialOffer(call, hctx)
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
            text = payload
        )
    }

    private suspend fun handleResponseToAuthorizationRequest(call: RoutingCall) {

        val ctx = HolderContext.instanceHack
            ?: throw IllegalStateException("No HolderContext")

        val queryParams = urlQueryToMap(call.request.uri)
        OAuthActions.handleIDTokenExchange(ctx, queryParams)

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
    private suspend fun handleCredentialOffer(call: RoutingCall, ctx: HolderContext) {

        // Get Credential Offer URI from the query Parameters
        //
        val credOfferUri = call.request.queryParameters["credential_offer_uri"]
            ?: throw HttpStatusException(HttpStatusCode.BadRequest, "No 'credential_offer_uri' param")

        val oid4vcOfferUri = "openid-credential-offer://?credential_offer_uri=$credOfferUri"

        val credOffer = HolderActions.fetchCredentialOfferFromUri(oid4vcOfferUri)
        val offeredCred = HolderActions.resolveOfferedCredentials(ctx, credOffer)
        val authRequest = HolderActions.authorizationRequestFromCredentialOffer(ctx, offeredCred)
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

    suspend fun resolveLoginContext(walletId: String) : LoginContext {

        // We expect the user to have logged in previously and have a valid Did
        //
        var ctx = LoginContext.findLoginContextByWalletId(walletId)

        // Fallback
        if (ctx == null) {
            val cfg = ConfigProvider.requireHolderConfig()
            if (cfg.userEmail.isNotBlank() && cfg.userPassword.isNotBlank()) {
                val loginParams = LoginParams(LoginType.EMAIL, cfg.userEmail, cfg.userPassword)
                walletService.loginWallet(loginParams)
                ctx = walletService.getLoginContext()
            }
        }

        ctx ?: throw IllegalStateException("Login required")

        if (!ctx.hasDidInfo) {
            ctx.didInfo = walletService.findDidByPrefix("did:key")
                ?: throw IllegalStateException("Cannot find required did in wallet")
        }

        return ctx
    }

    // Issuer ----------------------------------------------------------------------------------------------------------

    private fun getCookieDataFromSession(call: RoutingCall): CookieData? {
        val dat = call.sessions.get(CookieData.NAME)
        return dat as? CookieData
    }

    private fun setCookieDataInSession(call: RoutingCall, dat: CookieData) {
        call.sessions.set(CookieData.NAME, dat)
    }

    private fun getLoginContextFromSession(call: RoutingCall): LoginContext? {
        val dat = getCookieDataFromSession(call)
        val ctx = dat?.let { LoginContext.findLoginContextByWalletId(it.wid) }
        return ctx
    }

    private suspend fun handleIssuerMetadata(call: RoutingCall) {

        val payload = Json.encodeToString(IssuerActions.issuerMetadata)
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }

    @Serializable
    data class CookieData(val wid: String, val did: String?) {
        companion object {
            const val NAME = "CookieData"
        }
    }
}

