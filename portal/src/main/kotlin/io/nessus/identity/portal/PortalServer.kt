package io.nessus.identity.portal

import com.nimbusds.jwt.SignedJWT
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
import io.nessus.identity.service.DidInfo
import io.nessus.identity.service.LoginParams
import io.nessus.identity.service.LoginType
import io.nessus.identity.service.ServiceManager.walletService
import io.nessus.identity.service.WalletInfo
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
                cookie<UserSession>(UserSession.NAME) {
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
                    getUserSession(call)?.close()
                    call.sessions.clear(UserSession.NAME)
                    handleHome(call)
                }
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
        val session = getUserSession(call)
        call.respond(
            FreeMarkerContent(
                template = "index.ftl",
                model = mapOf(
                    "walletInfo" to session?.walletInfo,
                    "did" to session?.didInfo?.did,
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

        val walletInfo = runBlocking {
            walletService.loginWallet(LoginParams(LoginType.EMAIL, email, password))
        }

        val session = UserSession(walletInfo)
        call.sessions.set(UserSession.NAME, session)

        runBlocking {
            session.didInfo = walletService.findDidByPrefix(walletInfo.id, "did:key")
        }

        handleHome(call)
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
            text = payload
        )
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

        val ctx = CredentialOfferContext()
        val oid4vcOfferUri = "openid-credential-offer://?credential_offer_uri=$credOfferUri"

        val credOffer = HolderActions.fetchCredentialOfferFromUri(oid4vcOfferUri)
        val offeredCred = HolderActions.resolveOfferedCredentials(ctx, credOffer).also {
            resolveUserSession(call, ctx)
        }
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

    suspend fun resolveUserSession(call: RoutingCall, ctx: CredentialOfferContext) {

        // Derive subject id from issuer state (if possible)
        //
        if (!ctx.didInfoAvailable) {
            val subDid = ctx.credentialOffer.grants.values
                .mapNotNull { runCatching { SignedJWT.parse(it.issuerState) }.getOrNull() }
                .onEach { HolderActions.log.info { "IssuerState JWT: ${it.jwtClaimsSet}"} }
                .map { it.jwtClaimsSet.subject }
                .firstOrNull { it.startsWith("did:key") }
                ?: throw IllegalStateException("Cannot derive target subject")
            // Find the user session for portal login
            var walletInfo = UserSession.findWalletInfoByDid(subDid)
            // Fallback to globally configured credentials
            if (walletInfo == null) {
                val cfg = ConfigProvider.requireHolderConfig()
                val loginParams = LoginParams(LoginType.EMAIL, cfg.userEmail, cfg.userPassword)
                walletInfo = walletService.loginWallet(loginParams)
            }
            val didInfo = walletService.findDidByPrefix(walletInfo.id, subDid)
                ?: throw IllegalStateException("Cannot find did in wallet")

            SimpleSession.putCredentialOfferContext(subDid, ctx)
            ctx.walletInfo = walletInfo
            ctx.didInfo = didInfo
        }

        val session = UserSession(ctx.walletInfo)
        call.sessions.set(UserSession.NAME, session)
    }

    // Issuer ----------------------------------------------------------------------------------------------------------

    private fun getUserSession(call: RoutingCall) : UserSession? {
        return call.sessions.get(UserSession.NAME) as? UserSession
    }

    private suspend fun handleIssuerMetadata(call: RoutingCall) {

        val payload = Json.encodeToString(IssuerActions.issuerMetadata)
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = payload
        )
    }
}

@Serializable
class UserSession {

    companion object {
        const val NAME = "UserSession"
        private val store = mutableMapOf<String, UserSession>()
        fun findWalletInfoByDid(did : String) : WalletInfo? {
            val userSession = store.values.firstOrNull { us -> us.didInfo?.did == did }
            return userSession?.walletInfo
        }
    }

    val walletInfo: WalletInfo
    var didInfo: DidInfo? = null

    constructor(walletInfo: WalletInfo) {
        this.walletInfo = walletInfo
        store[walletInfo.name] = this
    }
    
    fun close() {
        store.remove(walletInfo.name)
    }
}