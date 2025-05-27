package io.nessus.identity.proxy

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.forms.FormDataContent
import io.ktor.client.request.get
import io.ktor.client.request.post
import io.ktor.client.request.setBody
import io.ktor.client.statement.bodyAsText
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
import io.nessus.identity.proxy.HttpProvider.http
import kotlinx.serialization.json.Json
import io.nessus.identity.service.ConfigProvider.config
import io.nessus.identity.service.ConfigProvider.mainConfig
import io.nessus.identity.service.DidInfo
import io.nessus.identity.service.LoginParams
import io.nessus.identity.service.LoginType
import io.nessus.identity.service.ServiceManager
import io.nessus.identity.service.WalletInfo
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.io.File
import java.net.URI
import java.net.URLDecoder
import java.security.KeyStore
import java.time.Instant
import java.util.Date

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
        val walletService = ServiceManager.walletService
    }

    val walletInfo: WalletInfo
    val didInfo: DidInfo

    constructor() {
        log.info { "Starting OID4VC Server ..." }
        log.info { "BaseUrl: ${config.baseUrl}" }

        walletInfo = runBlocking {
            walletService.loginWallet(
                LoginParams(
                    LoginType.EMAIL,
                    config.userEmail,
                    config.userPassword
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

        val host = mainConfig.getString("server.host")
        val port = mainConfig.getInt("server.port")
        val tls = mainConfig.getBoolean("tls.enabled")

        embeddedServer(Netty, configure = {
            if (tls) {
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
    //
    // Issuer initiated flows start with the Credential Offering proposed by Issuer.
    // The Credential Offering is in redirect for same-device tests and in QR Code for cross-device tests.
    // Expected Credential Offering endpoint may be given in the test scenario, while it defaults to openid-credential-offer://
    //
    suspend fun handleReceiveCredentialOffer(call: RoutingCall) {
        val oid4vc = NessusOpenID4VC(walletInfo, didInfo)

        // Get Credential Offer URI from the query Parameters
        //
        val credOfferUri = call.request.queryParameters["credential_offer_uri"]
            ?: throw HttpStatusException(HttpStatusCode.BadRequest, "No 'credential_offer_uri' param")

        // Parse and resolve the CredentialOfferUri into a CredentialOffer
        //
        val credOffer = oid4vc.receiveCredentialOfferUri(credOfferUri)

        // Process the CredentialOffer and create a CredentialOfferContext
        //
        oid4vc.receiveCredentialOffer(credOffer)

        // Handle in-time issuance of the credential and DID authentication through an IDToken.

        val authCode = oid4vc.sendAuthorizationRequest()
        val tokenResponse = oid4vc.sendTokenRequest(authCode)
        val credResponse = oid4vc.sendCredentialRequest(tokenResponse)

        val format = credResponse.format
        val credential = SignedJWT.parse(credResponse.credential)
        walletService.addCredential(walletInfo.id, format, credential)

        // Respond to the caller with 202 Accepted
        call.respondText(
            status = HttpStatusCode.Accepted,
            contentType = ContentType.Application.Json,
            text = "${credential.jwtClaimsSet}"
        )
    }
}

fun createFlattenedJwsJson(jwtHeader: JWSHeader, jwtClaims: JWTClaimsSet): JsonObject {
    val headerBase64 = Base64URL.encode(jwtHeader.toString())
    val payloadBase64 = Base64URL.encode(jwtClaims.toPayload().toString())
    return buildJsonObject {
        put("protected", JsonPrimitive(headerBase64.toString()))
        put("payload", JsonPrimitive(payloadBase64.toString()))
    }
}

fun urlQueryToMap(url: String): Map<String, String> {
    return URI(url).rawQuery?.split("&")?.associate { p ->
        p.split("=", limit = 2).let { (k, v) -> k to URLDecoder.decode(v, "UTF-8") }
    } ?: mapOf()
}

fun verifyJwt(encodedJwt: String, didInfo: DidInfo): Boolean {

    val signedJWT = SignedJWT.parse(encodedJwt)

    val docJson = Json.parseToJsonElement(didInfo.document).jsonObject
    val verificationMethods = docJson["verificationMethod"] as JsonArray
    val verificationMethod = verificationMethods.let { it[0] as JsonObject }
    val publicKeyJwk = Json.encodeToString(verificationMethod["publicKeyJwk"])

    val publicJwk = ECKey.parse(publicKeyJwk)
    val verifier = ECDSAVerifier(publicJwk)
    return signedJWT.verify(verifier)
}
