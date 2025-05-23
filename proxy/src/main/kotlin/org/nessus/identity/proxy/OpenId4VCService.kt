package org.nessus.identity.proxy

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory
import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.responses.TokenResponse
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.*
import io.ktor.client.engine.cio.*
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.ktor.serialization.kotlinx.json.*
import io.ktor.server.application.*
import io.ktor.server.engine.*
import io.ktor.server.netty.*
import io.ktor.server.plugins.contentnegotiation.*
import io.ktor.server.request.*
import io.ktor.server.response.*
import io.ktor.server.routing.*
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.ExperimentalCoroutinesApi
import kotlinx.coroutines.isActive
import kotlinx.coroutines.runBlocking
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import org.nessus.identity.service.DidInfo
import org.nessus.identity.service.LoginParams
import org.nessus.identity.service.LoginType
import org.nessus.identity.service.WalletService
import java.io.File
import java.net.URI
import java.net.URLDecoder
import java.security.KeyStore
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import java.util.Date
import kotlin.random.Random

fun main() {
    OpenId4VCService().runServer()
}

class OpenId4VCService {

    var httpClient: HttpClient? = null

    // Progress state
    var issuerMetadata: OpenIDProviderMetadata? = null
    var authorizationServer: String? = null
    var codeVerifier: String? = null

    // TokenResponse available on successful authentication
    val deferredTokenResponse = CompletableDeferred<TokenResponse>()

    companion object {
        val log = KotlinLogging.logger {}


        val config: Config get() = loadConfig().getConfig("proxy")
        val externalUrl = config.getString("server.external_url")
        val authCallbackUrl = "$externalUrl/auth-callback"

        val walletSvc = WalletService.build(config.getString("walt.wallet-api"))
        val walletInfo = runBlocking {
            walletSvc.loginWallet(
                LoginParams(
                    LoginType.EMAIL,
                    config.getString("walt.user_email"),
                    config.getString("walt.user_password")
                )
            )
        }
        val didInfo = runBlocking {
            walletSvc.findDidByPrefix(walletInfo.id, "did:key")
                ?: throw IllegalStateException("No did:key in wallet: ${walletInfo.id}")
        }

        fun loadConfig() : Config {

            val envVars = System.getenv()
            val baseCfg = ConfigFactory.load()
            val mergedCfg = mutableMapOf<String, String>()

            // Recursively collect all keys in base config
            fun flatten(prefix: String, cfg: Config) {
                for (entry in cfg.entrySet()) {
                    val fullKey = if (prefix.isEmpty()) entry.key else "$prefix.${entry.key}"
                    val envKey = fullKey.uppercase().replace('.', '_').replace('-', '_')
                    mergedCfg[fullKey] = envVars[envKey] ?: baseCfg.getValue(fullKey).unwrapped().toString()
                }
            }
            flatten("", baseCfg)
            return ConfigFactory.parseMap(mergedCfg)
        }
    }

    fun runServer() {

        val host = config.getString("server.host")
        val port = config.getInt("server.port")

        val tlsEnabled = config.getBoolean("tls.enabled")

        log.info { "Starting OID4VC Server ..." }
        log.info { "Wallet: ${walletInfo.id}" }
        log.info { "Did:    ${didInfo.did}" }

        embeddedServer(Netty, configure = {
            if (tlsEnabled) {
                val keyAlias = config.getString("tls.key_alias")
                val keystoreFile = config.getString("tls.keystore_file")
                val keystorePassword = config.getString("tls.keystore_password").toCharArray()
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
            routing {
                get("/openid-credential-offer") {
                    receiveOpenIdCredentialOffer(call)
                }
                get("/auth-callback") {
                    handleAuthCallback(call)
                }
                get("{...}") {
                    handleHome(call)
                }
            }
        }.start(wait = true)
    }

    suspend fun handleHome(call: RoutingCall) {
        log.info { call.request.uri }
        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Text.Plain,
            text = "EBSI OpenID4VC and Wallet Proxy\n"
        )
    }

    @OptIn(ExperimentalCoroutinesApi::class)
    suspend fun handleAuthCallback(call: RoutingCall) {

        val clientId = didInfo.did

        call.request.queryParameters["error"]?.let { err ->
            val description = call.request.queryParameters["error_description"]
            return call.respondText(
                status = HttpStatusCode.Found,
                contentType = ContentType.Text.Plain,
                text = "Error: $err\nDescription: $description"
            )
        }

        // Authentication Code Flow ====================================================================================

        val code = urlQueryToMap(call.request.uri)["code"]
            ?: throw IllegalStateException("Cannot find code")

        codeVerifier
            ?: throw IllegalStateException("No code_verifier")

        val res = http().post("$authorizationServer/token") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                append("grant_type", "authorization_code")
                append("client_id", clientId)
                append("code", code)
                append("code_verifier", codeVerifier!!)
                append("redirect_uri", authCallbackUrl)
            }))
        }

        if (res.status != HttpStatusCode.OK) {
            return respondWithBadRequest(call, res)
        }

        val tokenResponse = TokenResponse.fromJSONString(res.bodyAsText()).also {
            deferredTokenResponse.complete(it)
        }
        val tokenResponseJson = Json.encodeToString(tokenResponse)
        log.info { "TokenResponse: $tokenResponseJson" }

        call.respondText(
            status = HttpStatusCode.OK,
            contentType = ContentType.Application.Json,
            text = tokenResponseJson
        )
    }

    // Request and present Verifiable Credentials
    // https://hub.ebsi.eu/conformance/build-solutions/holder-wallet-functional-flows
    suspend fun receiveOpenIdCredentialOffer(call: RoutingCall) {

        val walletId = walletInfo?.id ?: throw IllegalStateException("No suitable Wallet")
        val clientId = didInfo?.did ?: throw IllegalStateException("No suitable DID")
        val didDocument = didInfo!!.document

        // Receive Credential Offer ====================================================================================
        //
        // Set the Credential Offer endpoint to this path handler
        // e.g. http://localhost:9000/openid-credential-offer

        val credOfferUri = call.request.queryParameters["credential_offer_uri"] ?: run {
            call.respond(HttpStatusCode.BadRequest, "Missing param: credential_offer_uri")
            return
        }

        val oid4vcOfferUri = "openid-credential-offer://?credential_offer_uri=$credOfferUri"
        log.info { "Received: $oid4vcOfferUri" }

        // Fetch the credential offer
        //
        val credentialOffer = OpenID4VCI.parseAndResolveCredentialOfferRequestUrl(oid4vcOfferUri)
        val credOfferJson = Json.encodeToString(credentialOffer)
        log.info { "Received credential offer: $credOfferJson}" }

        // Extract issuer_state from the offer
        val issuerState = credentialOffer.grants[GrantType.authorization_code.value]?.issuerState
            ?: throw NoSuchElementException("Missing authorization_code.issuer_state")

        // Issuer Metadata Discovery ===================================================================================
        // https://api-conformance.ebsi.eu/conformance/v3/issuer-mock/.well-known/openid-credential-issuer

        issuerMetadata = resolveOpenIDProviderMetadata(credentialOffer.credentialIssuer)
        val issuerMetadataJson = Json.encodeToString(issuerMetadata)
        log.info { "Received issuer metadata: $issuerMetadataJson" }

        val draft11Metadata = issuerMetadata as? OpenIDProviderMetadata.Draft11
            ?: throw IllegalStateException("Expected Draft11 metadata, but got ${issuerMetadata!!::class.simpleName}")

        val credentialIssuerUri = draft11Metadata.credentialIssuer
            ?: throw IllegalStateException("Cannot obtain credential_issuer from: $issuerMetadata")

        val credentialEndpointUri = draft11Metadata.credentialEndpoint
            ?: throw IllegalStateException("Cannot obtain credential_endpoint from: $issuerMetadata")

        // Get authorizationServer from /issuer-mock metadata
        authorizationServer = draft11Metadata.authorizationServer
            ?: throw IllegalStateException("Cannot obtain authorization_server from: $issuerMetadata")

        // Resolve Offered Credential ==================================================================================
        //
        val offeredCredentials = OpenID4VCI.resolveOfferedCredentials(credentialOffer, draft11Metadata)
        log.info { "Received offered credentials: ${Json.encodeToString(offeredCredentials)}" }
        if (offeredCredentials.size > 1) log.warn { "Multiple offered credentials, using first" }
        val offeredCredential = offeredCredentials.first()

        // Authorization ===============================================================================================

        // Build Authorization Request ----------------------------------------------------------------------------------
        //

        val rndBytes = Random.Default.nextBytes(32)
        codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(rndBytes)
        val sha256 = MessageDigest.getInstance("SHA-256")
        val codeVerifierHash = sha256.digest(codeVerifier!!.toByteArray(Charsets.US_ASCII))
        val codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifierHash)

        val credentialTypes = offeredCredential.types ?: throw IllegalStateException("No credential types")

        val authReqMap = linkedMapOf(
            "response_type" to "code",
            "scope" to "openid",
            "client_id" to clientId,
            "code_challenge" to codeChallenge,
            "code_challenge_method" to "S256",
            "authorization_details" to Json.encodeToString(
                listOf(
                    AuthorizationDetail(
                        format = "jwt_vc",
                        type = "openid_credential",
                        types = credentialTypes
                    )
                )
            ),
            "redirect_uri" to authCallbackUrl,
            "issuer_state" to issuerState,
        ).toMutableMap()

        // Build and log Authorization Request Url
        val authReqUrl = URLBuilder("$authorizationServer/authorize").apply {
            authReqMap.forEach { (k, v) -> parameters.append(k, v) }
        }.buildString()

        log.info { "AuthRequest: $authReqUrl" }
        urlQueryToMap(authReqUrl).forEach { (k, v) -> log.info { "  $k=$v" } }

        // Send Authorization Request ----------------------------------------------------------------------------------
        //

        var res = http().get(authReqUrl)

        // Process AuthRequest Redirect --------------------------------------------------------------------------------
        //

        var location = res.headers["location"] ?: run {
            return respondWithBadRequest(call, res)
        }
        log.info { "AuthRequest Redirect: $location" }

        val authReqRedirectParams = urlQueryToMap(location).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }
        authReqRedirectParams["error"]?.also {
            return respondWithBadRequest(call, res)
        }

        val requestUri = authReqRedirectParams["request_uri"]
            ?: throw IllegalStateException("Cannot find request_uri")

        // Send AuthRequest Redirect -----------------------------------------------------------------------------------
        //

        res = http().get(requestUri)

        if (res.status != HttpStatusCode.OK) {
            return respondWithBadRequest(call, res)
        }

        // Process ID Token Request ------------------------------------------------------------------------------------
        //

        val signedJWT = SignedJWT.parse(res.bodyAsText())
        log.info { "IDTokenReq Header: ${signedJWT.header}" }
        log.info { "IDTokenReq Claims: ${signedJWT.jwtClaimsSet}" }

        val authAud = authReqRedirectParams["client_id"] ?: throw IllegalStateException("Cannot find client_id")
        val nonce = authReqRedirectParams["nonce"] ?: throw IllegalStateException("Cannot find nonce")
        val state = authReqRedirectParams["state"] ?: throw IllegalStateException("Cannot find state")
        val redirectUri =
            authReqRedirectParams["redirect_uri"] ?: throw IllegalStateException("Cannot find redirect_uri")

        var now = Instant.now()
        var iat = Date.from(now)
        var exp = Date.from(now.plusSeconds(300)) // 5 mins expiry

        val docJson = Json.parseToJsonElement(didDocument).jsonObject
        val authentication = (docJson["authentication"] as JsonArray).let { it[0].jsonPrimitive.content }

        val idTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(authentication)
            .build()

        val idTokenClaims = JWTClaimsSet.Builder()
            .issuer(clientId)
            .subject(clientId)
            .audience(authAud)
            .issueTime(iat)
            .expirationTime(exp)
            .claim("nonce", nonce)
            .claim("state", state)
            .build()

        val idTokenJwt = SignedJWT(idTokenHeader, idTokenClaims)
        log.info { "IDTokenRes Header: ${idTokenJwt.header}" }
        log.info { "IDTokenRes Claims: ${idTokenJwt.jwtClaimsSet}" }

        val idTokenSigningInput = Json.encodeToString(createFlattenedJwsJson(idTokenHeader, idTokenClaims))
        val idToken = walletSvc.signWithKey(walletId, authentication, idTokenSigningInput)

        log.info { "IDToken Input: $idTokenSigningInput" }
        log.info { "IDToken: $idToken" }

        if (!verifyJwt(idToken, didInfo!!))
            log.warn { "Signature verification failed" }

        // Send ID Token Response --------------------------------------------------------------------------------------
        //

        res = http().post(redirectUri) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                append("id_token", idToken)
                append("state", state)
            }))
        }

        location = res.headers["location"] ?: run {
            return respondWithBadRequest(call, res)
        }

        log.info { "IDToken Redirect: $location" }

        if (!location.startsWith(authCallbackUrl))
            throw IllegalStateException("Unexpected redirect Uri: $location")

        urlQueryToMap(location)["code"]
            ?: throw IllegalStateException("Cannot find code")

        call.respondRedirect(location)

        val tokenResponse = deferredTokenResponse.await()

        // Credential Request ==========================================================================================
        //

        // The Relying Party proceeds by requesting issuance of the Verifiable Credential from the Issuer Mock.
        // The requested Credential must match the granted access. The DID document's authentication key must be used for signing the JWT proof,
        // where the DID must also match the one used for authentication.

        now = Instant.now()
        iat = Date.from(now)
        exp = Date.from(now.plusSeconds(300)) // 5 mins expiry

        val credReqHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("openid4vci-proof+jwt"))
            .keyID(authentication)
            .build()

        val credReqClaims = JWTClaimsSet.Builder()
            .issuer(clientId)
            .audience(credentialIssuerUri)
            .issueTime(iat)
            .expirationTime(exp)
            .claim("nonce", nonce)
            .claim("state", state)
            .build()

        val credReqInput = Json.encodeToString(createFlattenedJwsJson(credReqHeader, credReqClaims))
        val signedCredReqBase64 = walletSvc.signWithKey(walletId, authentication, credReqInput)
        log.info { "CredentialReq JWT: $signedCredReqBase64" }
        val signedCredReqJwt = SignedJWT.parse(signedCredReqBase64)
        log.info { "CredentialReq Header: ${signedCredReqJwt.header}" }
        log.info { "CredentialReq Claims: ${signedCredReqJwt.jwtClaimsSet}" }

        val credReqBody = Json.encodeToString(buildJsonObject {
            put("types", JsonArray(credentialTypes.map { JsonPrimitive(it) }))
            put("format", JsonPrimitive("jwt_vc"))
            put("proof", buildJsonObject {
                put("proof_type", JsonPrimitive("jwt"))
                put("jwt", JsonPrimitive(signedCredReqBase64))
            })
        })

        val accessToken = tokenResponse.accessToken
        log.info { "AccessToken: $accessToken" }

        res = http().post(credentialEndpointUri) {
            header(HttpHeaders.Authorization, "Bearer $accessToken")
            contentType(ContentType.Application.Json)
            setBody(credReqBody)
        }

        if (res.status != HttpStatusCode.OK) {
            return respondWithBadRequest(call, res)
        }

        val resJson = res.bodyAsText()
        log.info { "${res.status} $resJson" }

        call.respondText(
            status = res.status,
            contentType = ContentType.Application.Json,
            text = resJson
        )
    }

    suspend fun resolveOpenIDProviderMetadata(issuerUrl: String): OpenIDProviderMetadata {
        val issuerMetadataUrl = "$issuerUrl/.well-known/openid-credential-issuer"
        return http().get(issuerMetadataUrl).bodyAsText().let {

            // [TODO] Remove the trust_framework hack when this is fixed
            // Cannot resolve EBSI issuer metadata
            // https://github.com/walt-id/waltid-identity/issues/1065
            val filteredJson = removeKeyRecursive(it, "trust_framework")

            OpenIDProviderMetadata.fromJSONString(filteredJson)
        }
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun http(): HttpClient {
        if (httpClient == null || !httpClient!!.isActive) {
            httpClient = HttpClient(CIO) {
                install(io.ktor.client.plugins.contentnegotiation.ContentNegotiation) {
                    json()
                }
            }
        }
        return httpClient!!
    }

    fun createFlattenedJwsJson(jwtHeader: JWSHeader, jwtClaims: JWTClaimsSet): JsonObject {
        val headerBase64 = Base64URL.encode(jwtHeader.toString())
        val payloadBase64 = Base64URL.encode(jwtClaims.toPayload().toString())
        return buildJsonObject {
            put("protected", JsonPrimitive(headerBase64.toString()))
            put("payload", JsonPrimitive(payloadBase64.toString()))
        }
    }

    private fun removeKeyRecursive(rawJson: String, keyToRemove: String): String {
        val jel = removeKeyRecursive(Json.parseToJsonElement(rawJson), keyToRemove)
        return Json.encodeToString(JsonElement.serializer(), jel)
    }

    private fun removeKeyRecursive(element: JsonElement, keyToRemove: String): JsonElement {
        return when (element) {
            is JsonObject -> JsonObject(
                element.filterKeys { it != keyToRemove }
                    .mapValues { (_, v) -> removeKeyRecursive(v, keyToRemove) }
            )

            is JsonArray -> JsonArray(element.map { removeKeyRecursive(it, keyToRemove) })
            else -> element
        }
    }

    private suspend fun respondWithBadRequest(call: RoutingCall, res: HttpResponse) {
        val resJson = res.bodyAsText()
        log.info { "${res.status} $resJson" }
        call.respondText(
            status = HttpStatusCode.BadRequest,
            contentType = ContentType.Application.Json,
            text = resJson
        )
    }

    private fun urlQueryToMap(url: String): Map<String, String> {
        return URI(url).rawQuery?.split("&")?.associate { p ->
            p.split("=", limit = 2).let { (k, v) -> k to URLDecoder.decode(v, "UTF-8") }
        } ?: mapOf()
    }

    private fun verifyJwt(encodedJwt: String, didInfo: DidInfo): Boolean {

        val signedJWT = SignedJWT.parse(encodedJwt)

        val docJson = Json.parseToJsonElement(didInfo.document).jsonObject
        val verificationMethods = docJson["verificationMethod"] as JsonArray
        val verificationMethod = verificationMethods.let { it[0] as JsonObject }
        val publicKeyJwk = Json.encodeToString(verificationMethod["publicKeyJwk"])

        val publicJwk = ECKey.parse(publicKeyJwk)
        val verifier = ECDSAVerifier(publicJwk)
        return signedJWT.verify(verifier)
    }

}

@Serializable
data class AuthorizationDetail(
    val type: String,
    val format: String,
    val types: List<String>
)