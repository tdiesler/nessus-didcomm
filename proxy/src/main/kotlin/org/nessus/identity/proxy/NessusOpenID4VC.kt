package org.nessus.identity.proxy

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.crypto.ECDSAVerifier
import com.nimbusds.jose.jwk.ECKey
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OfferedCredential
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.responses.TokenResponse
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.request.forms.FormDataContent
import io.ktor.client.statement.*
import io.ktor.http.*
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
import org.nessus.identity.proxy.ConfigProvider.config
import org.nessus.identity.proxy.HttpProvider.http
import org.nessus.identity.service.DidInfo
import org.nessus.identity.service.LoginParams
import org.nessus.identity.service.LoginType
import org.nessus.identity.service.WalletService
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import java.util.Date
import kotlin.collections.component1
import kotlin.collections.component2
import kotlin.random.Random

object NessusOpenID4VC {

    val log = KotlinLogging.logger {}

    val walletSvc = WalletService.build(config.walletApi)
    val walletInfo = runBlocking {
        walletSvc.loginWallet(
            LoginParams(
                LoginType.EMAIL,
                config.userEmail,
                config.userPassword
            )
        )
    }
    val didInfo = runBlocking {
        walletSvc.findDidByPrefix(walletInfo.id, "did:key")
            ?: throw IllegalStateException("No did:key in wallet: ${walletInfo.id}")
    }

    init {
        log.info { "Wallet: ${walletInfo.id}" }
        log.info { "Did:    ${didInfo.did}" }
    }

    /**
     * The Authorisation Request builds on the OAuth 2.0 Rich Authorisation Request, where the user specifies which
     * where the user specifies which types of VCs they are requesting using the authorization_details parameter.
     * https://hub.ebsi.eu/conformance/learn/verifiable-credential-issuance#authorisation-request
     *
     * @return The OAuth 2.0 authorization code
     */
    suspend fun sendAuthorizationRequest(ctx: CredentialOfferContext) :String {

        val rndBytes = Random.Default.nextBytes(32)
        val codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(rndBytes)
        val sha256 = MessageDigest.getInstance("SHA-256")
        val codeVerifierHash = sha256.digest(codeVerifier.toByteArray(Charsets.US_ASCII))
        val codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifierHash)

        ctx.extraState["AuthorizationRequest.codeVerifier"] = codeVerifier

        val credentialTypes = ctx.offeredCredential.types ?: throw IllegalStateException("No credential types")

        val authReqMap = linkedMapOf(
            "response_type" to "code",
            "scope" to "openid",
            "client_id" to didInfo.did,
            "code_challenge" to codeChallenge,
            "code_challenge_method" to "S256",
            "authorization_details" to Json.encodeToString(
                listOf(
                    AuthorizationDetail(
                        format = "jwt_vc",
                        type = "openid_credential",
                        types = credentialTypes,
                        locations = listOf(ctx.credentialIssuerUri),
                    )
                )
            ),
            "redirect_uri" to config.authCallbackUrl,
            "issuer_state" to ctx.issuerState,
        ).toMutableMap()

        // Build AuthRequestUrl
        val authReqUrl = URLBuilder("${ctx.authorizationServer}/authorize").apply {
            authReqMap.forEach { (k, v) -> parameters.append(k, v) }
        }.buildString()

        log.info { "AuthRequest: $authReqUrl" }
        urlQueryToMap(authReqUrl).forEach { (k, v) -> log.info { "  $k=$v" } }

        // Send AuthRequest --------------------------------------------------------------------------------------------
        //
        // AuthServer proceeds by requesting an ID Token from the Wallet to authenticate the DID without any claims.
        // This is delivered through redirection like any other delegation for authentication.

        var res = http().get(authReqUrl)
        if (res.status != HttpStatusCode.Found)
            throw HttpStatusException(res.status, res.bodyAsText())

        var queryParams = getRequestParamsFromLocationHeader(res).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        // Verify required query params
        for (key in listOf("client_id", "nonce", "state", "redirect_uri", "request_uri")) {
            queryParams[key] ?: throw IllegalStateException("Cannot find $key")
        }

        val authAud = queryParams["client_id"] as String
        val nonce = queryParams["nonce"] as String
        val state = queryParams["state"] as String
        val redirectUri = queryParams["redirect_uri"] as String
        val requestUri = queryParams["request_uri"] as String

        // Remember this state for the OfferRequest
        ctx.extraState["IDToken.state"] = state

        res = http().get(requestUri)
        if (res.status != HttpStatusCode.OK) 
            throw HttpStatusException(res.status, res.bodyAsText())

        val idTokenReq = res.bodyAsText()
        log.info { "IDTokenReq: $idTokenReq" }

        val signedJWT = SignedJWT.parse(idTokenReq)
        log.info { "IDTokenReq Header: ${signedJWT.header}" }
        log.info { "IDTokenReq Claims: ${signedJWT.jwtClaimsSet}" }

        val now = Instant.now()
        val iat = Date.from(now)
        val exp = Date.from(now.plusSeconds(300)) // 5 mins expiry

        val docJson = Json.parseToJsonElement(didInfo.document).jsonObject
        val authenticationId = (docJson["authentication"] as JsonArray).let { it[0].jsonPrimitive.content }

        val idTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(authenticationId)
            .build()

        val idTokenClaims = JWTClaimsSet.Builder()
            .issuer(didInfo.did)
            .subject(didInfo.did)
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
        val idToken = walletSvc.signWithKey(walletInfo.id, authenticationId, idTokenSigningInput)

        log.info { "IDToken Input: $idTokenSigningInput" }
        log.info { "IDToken: $idToken" }

        if (!verifyJwt(idToken, didInfo))
            log.warn { "Signature verification failed" }

        // Send IDToken Response --------------------------------------------------------------------------------------
        //
        log.info { "IDTokenRes: $redirectUri" }
        res = http().post(redirectUri) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                append("id_token", idToken)
                append("state", state)
            }))
        }

        if (res.status != HttpStatusCode.Found)
            throw HttpStatusException(res.status, res.bodyAsText())

        queryParams = getRequestParamsFromLocationHeader(res).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        val authCode = queryParams["code"] ?: throw IllegalStateException("No authorization code")
        return authCode
    }

    suspend fun sendTokenRequest(ctx: CredentialOfferContext, authCode: String) : TokenResponse {

        val ctx = SimpleSession.getCredentialOfferContext()
            ?: throw IllegalStateException("No CredentialOfferContext in session")

        val codeVerifier = ctx.extraState["AuthorizationRequest.codeVerifier"] as? String
            ?: throw IllegalStateException("No AuthorizationRequest.codeVerifier in context")

        // Authentication Code Flow ====================================================================================

        val res = http().post("${ctx.authorizationServer}/token") {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                append("grant_type", "authorization_code")
                append("client_id", didInfo.did)
                append("code", authCode)
                append("code_verifier", codeVerifier)
                append("redirect_uri", config.authCallbackUrl)
            }))
        }

        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val tokenResponseJson = res.bodyAsText()
        log.info { "TokenResponse: $tokenResponseJson" }

        val tokenResponse = TokenResponse.fromJSONString(tokenResponseJson).also {
            ctx.extraState["TokenResponse"] = it
        }

        return tokenResponse
    }

    /**
     * Parse and resolve the CredentialOfferUri into a CredentialOffer
     */
    suspend fun receiveCredentialOfferUri(credOfferUri: String): CredentialOffer {

        val oid4vcOfferUri = "openid-credential-offer://?credential_offer_uri=$credOfferUri"
        log.info { "Received: $oid4vcOfferUri" }

        // Parse the Credential Offer
        //
        return OpenID4VCI.parseAndResolveCredentialOfferRequestUrl(oid4vcOfferUri)
    }

    /**
     * Process the CredentialOffer and populate the CredentialOfferContext
     * Initial context stare is:
     *
     *      - CredentialOffer
     *      - OfferedCredential
     *      - OpenIDProviderMetadata (Issuer Metadata)
     */
    suspend fun receiveCredentialOffer(credOffer: CredentialOffer): CredentialOfferContext {

        val credOfferJson = Json.encodeToString(credOffer)
        log.info { "Received credential offer: $credOfferJson}" }

        // Get issuer Metadata =========================================================================================
        //
        val issuerMetadata = resolveOpenIDProviderMetadata(credOffer.credentialIssuer)
        val issuerMetadataJson = Json.encodeToString(issuerMetadata)
        log.info { "Received issuer metadata: $issuerMetadataJson" }

        val draft11Metadata = issuerMetadata as? OpenIDProviderMetadata.Draft11
            ?: throw IllegalStateException("Expected Draft11 metadata, but got ${issuerMetadata!!::class.simpleName}")

        // Resolve Offered Credential ==================================================================================
        //
        val offeredCredentials = OpenID4VCI.resolveOfferedCredentials(credOffer, draft11Metadata)
        log.info { "Received offered credentials: ${Json.encodeToString(offeredCredentials)}" }
        if (offeredCredentials.size > 1) log.warn { "Multiple offered credentials, using first" }
        val offeredCredential = offeredCredentials.first()

        val ctx = CredentialOfferContext(
            credentialOffer = credOffer,
            offeredCredential = offeredCredential,
            issuerMetadata = issuerMetadata,
        )
        SimpleSession.setCredentialOfferContext(ctx)

        return ctx
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

    suspend fun sendCredentialRequest(ctx: CredentialOfferContext, tokenResponse: TokenResponse) : SignedJWT {

        // The Relying Party proceeds by requesting issuance of the Verifiable Credential from the Issuer Mock.
        // The requested Credential must match the granted access. The DID document's authentication key must be used for signing the JWT proof,
        // where the DID must also match the one used for authentication.

        val accessToken = tokenResponse.accessToken
            ?: throw IllegalStateException("No accessToken")
        val cNonce = tokenResponse.cNonce
            ?: throw IllegalStateException("No c_nonce")

        val now = Instant.now()
        val iat = Date.from(now)
        val exp = Date.from(now.plusSeconds(300)) // 5 mins expiry

        val docJson = Json.parseToJsonElement(didInfo.document).jsonObject
        val authentication = (docJson["authentication"] as JsonArray).let { it[0].jsonPrimitive.content }

        val credReqHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("openid4vci-proof+jwt"))
            .keyID(authentication)
            .build()

        val state = ctx.extraState["IDToken.state"] as? String
            ?: throw IllegalStateException("No IDToken.state")
        val credentialTypes = ctx.offeredCredential.types
            ?: throw IllegalStateException("No credential types")

        val credReqClaims = JWTClaimsSet.Builder()
            .issuer(didInfo.did)
            .audience(ctx.credentialIssuerUri)
            .issueTime(iat)
            .expirationTime(exp)
            .claim("nonce", cNonce)
            .claim("state", state)
            .build()

        val credReqInput = Json.encodeToString(createFlattenedJwsJson(credReqHeader, credReqClaims))
        val signedCredReqBase64 = walletSvc.signWithKey(walletInfo.id, authentication, credReqInput)
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

        log.info { "CredentialReq Body: $credReqBody" }

        val res = http().post(ctx.credentialEndpointUri) {
            header(HttpHeaders.Authorization, "Bearer $accessToken")
            contentType(ContentType.Application.Json)
            setBody(credReqBody)
        }
        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val credJson = res.bodyAsText()
        log.info { "Credential: $credJson" }

        val credJsonObj = Json.parseToJsonElement(credJson) as JsonObject
        val format = (credJsonObj["format"] as JsonPrimitive).content
        val credentialBase64 = (credJsonObj["credential"] as JsonPrimitive).content

        if (format != "jwt_vc")
            throw IllegalStateException("Unsupported credential format: $format")

        val credJwt = SignedJWT.parse(credentialBase64)
        log.info { "CredentialReq Header: ${credJwt.header}" }
        log.info { "CredentialReq Claims: ${credJwt.jwtClaimsSet}" }

        return credJwt
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun createFlattenedJwsJson(jwtHeader: JWSHeader, jwtClaims: JWTClaimsSet): JsonObject {
        val headerBase64 = Base64URL.encode(jwtHeader.toString())
        val payloadBase64 = Base64URL.encode(jwtClaims.toPayload().toString())
        return buildJsonObject {
            put("protected", JsonPrimitive(headerBase64.toString()))
            put("payload", JsonPrimitive(payloadBase64.toString()))
        }
    }

    private fun getRequestParamsFromLocationHeader(res: HttpResponse): Map<String, String> {
        val location = res.headers["location"]?.also {
            log.info { "Response.Header.Location: $it" }
        } ?: throw IllegalStateException("Cannot find 'location' in headers")
        val paramsMap = urlQueryToMap(location)
        return paramsMap
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
    val types: List<String>,
    val locations: List<String>,
)

class CredentialOfferContext(
    val credentialOffer: CredentialOffer,
    val issuerMetadata: OpenIDProviderMetadata.Draft11,
    val offeredCredential: OfferedCredential,
    val extraState: MutableMap<String, Any> = mutableMapOf(),
) {

    val issuerState = credentialOffer.grants[GrantType.authorization_code.value]?.issuerState
        ?: throw NoSuchElementException("Missing authorization_code.issuer_state")

    // Get authorizationServer from /issuer-mock metadata
    val authorizationServer = issuerMetadata.authorizationServer
        ?: throw IllegalStateException("Cannot obtain authorization_server from: $issuerMetadata")

    val credentialIssuerUri = issuerMetadata.credentialIssuer
        ?: throw IllegalStateException("Cannot obtain credential_issuer from: $issuerMetadata")

    val credentialEndpointUri = issuerMetadata.credentialEndpoint
        ?: throw IllegalStateException("Cannot obtain credential_endpoint from: $issuerMetadata")
}

