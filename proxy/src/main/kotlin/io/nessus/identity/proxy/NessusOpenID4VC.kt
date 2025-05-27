package io.nessus.identity.proxy

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
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
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.nessus.identity.proxy.EBSIConformanceProxy.Companion.walletService
import io.nessus.identity.proxy.HttpProvider.http
import io.nessus.identity.service.ConfigProvider.config
import io.nessus.identity.service.DidInfo
import io.nessus.identity.service.LoginParams
import io.nessus.identity.service.LoginType
import io.nessus.identity.service.ServiceManager
import io.nessus.identity.service.WalletInfo
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonElement
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import java.util.Date
import kotlin.random.Random
import kotlin.uuid.ExperimentalUuidApi

class NessusOpenID4VC(val walletInfo: WalletInfo, val didInfo: DidInfo) {

    val walletService get() = ServiceManager.walletService
    private lateinit var context: CredentialOfferContext

    companion object {
        val log = KotlinLogging.logger {}
        suspend fun buildFromConfig(): NessusOpenID4VC {
            val walletInfo = walletService.loginWallet(
                LoginParams(
                    LoginType.EMAIL,
                    config.userEmail,
                    config.userPassword
                )
            )
            val didInfo = walletService.findDidByPrefix(walletInfo.id, "did:key")
                ?: throw IllegalStateException("No did:key in wallet: ${walletInfo.id}")
            return NessusOpenID4VC(walletInfo, didInfo)
        }
    }

    /**
     * The Authorisation Request builds on the OAuth 2.0 Rich Authorisation Request,
     * where the user specifies which types of VCs they are requesting using the authorization_details parameter.
     * https://hub.ebsi.eu/conformance/learn/verifiable-credential-issuance#authorisation-request
     *
     * @return The OAuth 2.0 authorization code
     */
    suspend fun sendAuthorizationRequest(): String {

        // The Wallet will start by requesting access for the desired credential from the Auth Mock (Authorisation Server).
        // The client_metadata.authorization_endpoint is used for the redirect location associated with the vp_token and id_token.
        // If client_metadata fails to provide the required information, the default configuration (openid://) will be used instead.

        val rndBytes = Random.Default.nextBytes(32)
        val codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(rndBytes)
        val sha256 = MessageDigest.getInstance("SHA-256")
        val codeVerifierHash = sha256.digest(codeVerifier.toByteArray(Charsets.US_ASCII))
        val codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifierHash)

        context.authRequestCodeVerifier = codeVerifier

        val credentialTypes = context.offeredCredential.types
            ?: throw IllegalStateException("No credential types")

        // Build AuthRequestUrl
        //
        val issuerUri = context.credentialIssuerUri
        val authServer = context.authorizationServer

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
                        locations = listOf(issuerUri),
                    )
                )
            ),
            "redirect_uri" to config.authCallbackUrl,
            "issuer_state" to context.issuerState,
        ).toMutableMap()

        val authReqUrl = URLBuilder("$authServer/authorize").apply {
            authReqMap.forEach { (k, v) -> parameters.append(k, v) }
        }.buildString()

        log.info { "GET AuthRequest: $authReqUrl" }
        urlQueryToMap(authReqUrl).forEach { (k, v) -> log.info { "  $k=$v" } }

        // Send AuthRequest
        // Since we don't set `client_metadata.authorization_endpoint` we expect to get a redirect
        var res = http().get(authReqUrl)
        if (res.status != HttpStatusCode.Found)
            throw HttpStatusException(res.status, res.bodyAsText())

        // Since we don't set
        var location = res.headers["location"]?.also {
            log.info { "AuthRequest Redirect: $it" }
        } ?: throw IllegalStateException("Cannot find 'location' in headers")

        var queryParams = urlQueryToMap(location).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        // The Wallet answers the ID Token Request by providing the id_token in the redirect_uri as instructed by response_mode of direct_post.
        // The id_token must be signed with the DID document's authentication key.

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
        context.authRequestState = state

        log.info { "GET IDTokenReq: $requestUri" }
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
        val idToken = EBSIConformanceProxy.Companion.walletService.signWithKey(
            walletInfo.id,
            authenticationId,
            idTokenSigningInput
        )

        log.info { "IDToken Input: $idTokenSigningInput" }
        log.info { "IDToken: $idToken" }

        if (!verifyJwt(idToken, didInfo))
            log.warn { "Signature verification failed" }

        // Send IDToken Response --------------------------------------------------------------------------------------
        //

        val formData = mapOf(
            "id_token" to idToken,
            "state" to state,
        )

        log.info { "POST IDTokenRes: $redirectUri" }
        formData.forEach { (k, v) -> log.info { "  $k=$v" } }

        res = http().post(redirectUri) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                formData.forEach { (k, v) -> append(k, v) }
            }))
        }

        if (res.status != HttpStatusCode.Found)
            throw HttpStatusException(res.status, res.bodyAsText())

        location = res.headers["location"]?.also {log.info { "AuthResponse: $it" } }
            ?: throw IllegalStateException("Cannot find 'location' in headers")

        queryParams = urlQueryToMap(location)
        return queryParams["code"] ?: throw IllegalStateException("No authorization code")
    }

    suspend fun sendTokenRequest(authCode: String): TokenResponse {

        // Authentication Code Flow ====================================================================================

        val codeVerifier = context.authRequestCodeVerifier
        val tokenReqUrl = "${context.authorizationServer}/token"

        val formData = mapOf(
            "grant_type" to "authorization_code",
            "client_id" to didInfo.did,
            "code" to authCode,
            "code_verifier" to codeVerifier,
            "redirect_uri" to config.authCallbackUrl,
        )

        log.info { "POST TokenRequest $tokenReqUrl" }
        log.info { "  $formData" }

        val res = http().post(tokenReqUrl) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                formData.forEach { (k, v) -> append(k, v) }
            }))
        }

        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val tokenResponseJson = res.bodyAsText()
        log.info { "TokenResponse: $tokenResponseJson" }

        val tokenResponse = TokenResponse.fromJSONString(tokenResponseJson).also {
            context.tokenResponse = it
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
     *
     * https://hub.ebsi.eu/conformance/learn/verifiable-credential-issuance#credential-offering
     */
    suspend fun receiveCredentialOffer(credentialOffer: CredentialOffer) {

        val credOfferJson = Json.encodeToString(credentialOffer)
        log.info { "Received credential offer: $credOfferJson}" }

        // Get issuer Metadata =========================================================================================
        //
        val issuerMetadata = resolveOpenIDProviderMetadata(credentialOffer.credentialIssuer)
        val issuerMetadataJson = Json.encodeToString(issuerMetadata)
        log.info { "Received issuer metadata: $issuerMetadataJson" }

        val draft11Metadata = issuerMetadata as? OpenIDProviderMetadata.Draft11
            ?: throw IllegalStateException("Expected Draft11 metadata, but got ${issuerMetadata::class.simpleName}")

        // Resolve Offered Credential ==================================================================================
        //
        val offeredCredentials = OpenID4VCI.resolveOfferedCredentials(credentialOffer, draft11Metadata)
        log.info { "Received offered credentials: ${Json.encodeToString(offeredCredentials)}" }
        if (offeredCredentials.size > 1) log.warn { "Multiple offered credentials, using first" }
        val offeredCredential = offeredCredentials.first()

        context = CredentialOfferContext(
            credentialOffer = credentialOffer,
            offeredCredential = offeredCredential,
            issuerMetadata = issuerMetadata
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

    @OptIn(ExperimentalUuidApi::class)
    suspend fun sendCredentialRequest(tokenResponse: TokenResponse): CredentialResponse {

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

        val state = context.authRequestState

        val credentialTypes = context.offeredCredential.types
            ?: throw IllegalStateException("No credential types")

        val issuerUri = context.credentialIssuerUri
        val credentialEndpointUri = context.credentialEndpointUri

        val credReqClaims = JWTClaimsSet.Builder()
            .issuer(didInfo.did)
            .audience(issuerUri)
            .issueTime(iat)
            .expirationTime(exp)
            .claim("nonce", cNonce)
            .claim("state", state)
            .build()

        val credReqInput = Json.encodeToString(createFlattenedJwsJson(credReqHeader, credReqClaims))
        val signedCredReqBase64 = walletService.signWithKey(walletInfo.id, authentication, credReqInput)
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

        log.info { "POST CredentialReq: $credentialEndpointUri" }
        log.info { "  $credReqBody" }

        val res = http().post(credentialEndpointUri) {
            header(HttpHeaders.Authorization, "Bearer $accessToken")
            contentType(ContentType.Application.Json)
            setBody(credReqBody)
        }
        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val credJson = res.bodyAsText()
        log.info { "Credential: $credJson" }

        val credRes = Json.decodeFromString<CredentialResponse>(credJson)
        val credJwt = SignedJWT.parse(credRes.credential)
        log.info { "CredentialReq Header: ${credJwt.header}" }
        log.info { "CredentialReq Claims: ${credJwt.jwtClaimsSet}" }

        return credRes
    }

    // Private ---------------------------------------------------------------------------------------------------------

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
}

// Types ===============================================================================================================

@Serializable
data class AuthorizationDetail(
    val type: String,
    val format: String,
    val types: List<String>,
    val locations: List<String>,
)

@Serializable
data class CredentialResponse(
    val format: String,
    val credential: String
)

class CredentialOfferContext(
    val credentialOffer: CredentialOffer,
    val issuerMetadata: OpenIDProviderMetadata.Draft11,
    val offeredCredential: OfferedCredential,
) {

    lateinit var authRequestState: String
    lateinit var authRequestCodeVerifier: String
    lateinit var tokenResponse: TokenResponse

    val issuerState = credentialOffer.grants[GrantType.authorization_code.value]?.issuerState
        ?: throw NoSuchElementException("Missing authorization_code.issuer_state")

    val authorizationServer = issuerMetadata.authorizationServer
        ?: throw IllegalStateException("Cannot obtain authorization_server from: $issuerMetadata")

    val credentialIssuerUri = issuerMetadata.credentialIssuer
        ?: throw IllegalStateException("Cannot obtain credential_issuer from: $issuerMetadata")

    val credentialEndpointUri = issuerMetadata.credentialEndpoint
        ?: throw IllegalStateException("Cannot obtain credential_endpoint from: $issuerMetadata")
}

