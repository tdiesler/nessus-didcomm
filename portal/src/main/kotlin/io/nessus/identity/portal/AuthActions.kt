package io.nessus.identity.portal

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.TokenResponse
import id.walt.oid4vc.util.http
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.nessus.identity.service.ConfigProvider.authEndpointUri
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.ServiceProvider.walletService
import io.nessus.identity.service.authenticationId
import io.nessus.identity.service.publicKeyJwk
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Instant
import java.util.Date
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

object AuthActions {

    val log = KotlinLogging.logger {}

    fun getAuthMetadataUrl(ctx: LoginContext): String {
        val metadataUrl = OpenID4VCI.getOpenIdProviderMetadataUrl("$authEndpointUri/${ctx.subjectId}")
        return metadataUrl
    }

    fun getAuthMetadata(ctx: LoginContext): JsonObject {
        val metadata = buildOAuthMetadata(ctx)
        return metadata
    }

    /**
     * Handle AuthorizationRequest currently from Holder Wallet to Issuer's Auth Endpoint
     */
    suspend fun handleAuthorizationRequest(cex: CredentialExchange, authReq: AuthorizationRequest): String {

        cex.authRequest = authReq
        cex.issuerMetadata = IssuerActions.getIssuerMetadata(cex)

        // Validate the AuthorizationRequest
        //
        // [TODO] check VC types in authorization_details

        val idTokenRedirectUrl = sendIDTokenRequest(cex, authReq)
        return idTokenRedirectUrl
    }

    @OptIn(ExperimentalUuidApi::class)
    suspend fun handleIDTokenResponse(cex: CredentialExchange, postParams: Map<String, List<String>>): String {

        val idToken = postParams["id_token"]?.firstOrNull()
            ?: throw IllegalStateException("No id_token")

        val idTokenJwt = SignedJWT.parse(idToken)
        log.info { "IDToken Header: ${idTokenJwt.header}" }
        log.info { "IDToken Claims: ${idTokenJwt.jwtClaimsSet}" }

        // [TODO] validate IDToken

        cex.authCode = "${Uuid.random()}"

        val authReq = cex.authRequest
        val idTokenResUrl = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("code", cex.authCode)
            authReq.state?.also { state ->
                parameters.append("state", state)
            }
        }.buildString()

        log.info { "IDToken Response $idTokenResUrl" }
        urlQueryToMap(idTokenResUrl).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return idTokenResUrl
    }

    @OptIn(ExperimentalUuidApi::class)
    suspend fun handleTokenRequest(cex: CredentialExchange, postParams: Map<String, List<String>>): TokenResponse {

        // Verify required post params
        for (key in listOf("client_id", "code", "code_verifier", "grant_type", "redirect_uri")) {
            postParams[key] ?: throw IllegalStateException("Cannot find $key")
        }

        val grantType = GrantType.fromValue(postParams["grant_type"]!!.first())
        val clientId = postParams["client_id"]!!.first()
        val code = postParams["code"]!!.first()
        val codeVerifier = postParams["code_verifier"]!!.first()
        val redirectUri = postParams["redirect_uri"]!!.first()

        // Verify token request
        //
        if (grantType != GrantType.authorization_code)
            throw IllegalArgumentException("Invalid grant_type: $grantType")
        if (clientId != cex.authRequest.clientId)
            throw IllegalArgumentException("Invalid client_id: $clientId")

        // [TODO] verify token request code challenge

        val keyJwk = cex.didInfo.publicKeyJwk()
        val kid = keyJwk["kid"]?.jsonPrimitive?.content as String

        val now = Instant.now()
        val expiresIn: Long = 86400
        val iat = Date.from(now)
        val exp = Date.from(now.plusSeconds(expiresIn))

        val nonce = "${Uuid.random()}"
        val authorizationDetails = cex.authRequest.authorizationDetails?.map { it.toJSON() }

        val tokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val tokenClaims = JWTClaimsSet.Builder()
            .issuer(cex.issuerMetadata.credentialIssuer)
            .subject(cex.authRequest.clientId)
            .issueTime(iat)
            .expirationTime(exp)
            .claim("nonce", nonce)
            .claim("authorization_details", authorizationDetails)
            .build()

        val rawTokenJwt = SignedJWT(tokenHeader, tokenClaims)
        log.info { "Token Header: ${rawTokenJwt.header}" }
        log.info { "Token Claims: ${rawTokenJwt.jwtClaimsSet}" }

        val signingInput = Json.encodeToString(createFlattenedJwsJson(tokenHeader, tokenClaims))
        val signedEncoded = walletService.signWithKey(kid, signingInput)
        val accessToken = SignedJWT.parse(signedEncoded)

        log.info { "Token: $signedEncoded" }
        if (!verifyJwt(accessToken, cex.didInfo))
            throw IllegalStateException("AccessToken signature verification failed")

        val tokenRespJson = """
            {
              "access_token": "$signedEncoded",
              "token_type": "bearer",
              "expires_in": $expiresIn,
              "c_nonce": "$nonce",
              "c_nonce_expires_in": $expiresIn
            }            
        """.trimIndent()

        val tokenResponse = TokenResponse.fromJSONString(tokenRespJson).also {
            cex.accessToken = accessToken
        }
        return tokenResponse
    }

    /**
     * Send ID Token request currently from Issuer's Auth Endpoint to Holder Wallet
     *
     * The Issuer's Authorisation Server validates the request and proceeds by requesting authentication of a DID from the client.
     * The ID Token Request also serves as an Authorisation Request and MUST be a signed Request Object.
     *
     * @return The wanted redirect url
     */
    suspend fun sendIDTokenRequest(cex: CredentialExchange, authReq: AuthorizationRequest): String {

        val issuerMetadata = cex.issuerMetadata
        val authorizationEndpoint = cex.authorizationEndpoint
        val keyJwk = cex.didInfo.publicKeyJwk()
        val kid = keyJwk["kid"]?.jsonPrimitive?.content as String

        val now = Instant.now()
        val iat = Date.from(now)
        val exp = Date.from(now.plusSeconds(300)) // 5 mins expiry

        val idTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        @OptIn(ExperimentalUuidApi::class)
        val idTokenClaims = JWTClaimsSet.Builder()
            .issuer(issuerMetadata.credentialIssuer)
            .audience(authReq.clientId)
            .issueTime(iat)
            .expirationTime(exp)
            .claim("response_type", "id_token")
            .claim("response_mode", "direct_post")
            .claim("client_id", issuerMetadata.credentialIssuer)
            .claim("redirect_uri", "$authorizationEndpoint/direct_post")
            .claim("scope", "openid")
            .claim("nonce", "${Uuid.random()}")
            .build()

        val idTokenJwt = SignedJWT(idTokenHeader, idTokenClaims)
        log.info { "IDToken Request Header: ${idTokenJwt.header}" }
        log.info { "IDToken Request Claims: ${idTokenJwt.jwtClaimsSet}" }

        val signingInput = Json.encodeToString(createFlattenedJwsJson(idTokenHeader, idTokenClaims))
        val signedEncoded = walletService.signWithKey(kid, signingInput)

        val idTokenRedirectUrl = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("client_id", authorizationEndpoint)
            parameters.append("response_type", "id_token")
            parameters.append("response_mode", "direct_post")
            parameters.append("scope", "openid")
            parameters.append("redirect_uri", "$authorizationEndpoint/direct_post")
            parameters.append("request", signedEncoded)
        }.buildString()

        log.info { "IDToken Request $idTokenRedirectUrl" }
        urlQueryToMap(idTokenRedirectUrl).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return idTokenRedirectUrl
    }

    suspend fun handleIDTokenExchange(cex: CredentialExchange, queryParams: Map<String, List<String>>): String {

        // Verify required query params
        for (key in listOf("client_id", "nonce", "state", "redirect_uri", "request_uri")) {
            queryParams[key] ?: throw IllegalStateException("Cannot find $key")
        }

        // The Wallet answers the ID Token Request by providing the id_token in the redirect_uri as instructed by response_mode of direct_post.
        // The id_token must be signed with the DID document's authentication key.

        val authAud = queryParams["client_id"]!!.first()
        val nonce = queryParams["nonce"]!!.first()
        val state = queryParams["state"]!!.first()
        val redirectUri = queryParams["redirect_uri"]!!.first()
        val requestUri = queryParams["request_uri"]!!.first()

        log.info { "Send IDToken Request: $requestUri" }
        var res = http.get(requestUri)
        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val idTokenReq = res.bodyAsText()
        log.info { "IDToken Response: $idTokenReq" }

        val signedJWT = SignedJWT.parse(idTokenReq)
        log.info { "IDTokenReq Header: ${signedJWT.header}" }
        log.info { "IDTokenReq Claims: ${signedJWT.jwtClaimsSet}" }

        val now = Instant.now()
        val iat = Date.from(now)
        val exp = Date.from(now.plusSeconds(300)) // 5 mins expiry

        val kid = cex.didInfo.authenticationId()

        val idTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val idTokenClaims = JWTClaimsSet.Builder()
            .issuer(cex.didInfo.did)
            .subject(cex.didInfo.did)
            .audience(authAud)
            .issueTime(iat)
            .expirationTime(exp)
            .claim("nonce", nonce)
            .claim("state", state)
            .build()

        val idTokenJwt = SignedJWT(idTokenHeader, idTokenClaims)
        log.info { "IDTokenRes Header: ${idTokenJwt.header}" }
        log.info { "IDTokenRes Claims: ${idTokenJwt.jwtClaimsSet}" }

        val signingInput = Json.encodeToString(createFlattenedJwsJson(idTokenHeader, idTokenClaims))
        val signedEncoded = walletService.signWithKey(kid, signingInput)

        log.info { "IDToken: $signedEncoded" }
        if (!verifyJwt(SignedJWT.parse(signedEncoded), cex.didInfo))
            throw IllegalStateException("IDToken signature verification failed")

        // Send IDToken Response --------------------------------------------------------------------------------------
        //

        val formData = mapOf(
            "id_token" to signedEncoded,
            "state" to state,
        )

        log.info { "Send IDToken Request: $redirectUri" }
        formData.forEach { (k, v) -> log.info { "  $k=$v" } }

        res = http.post(redirectUri) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                formData.forEach { (k, v) -> append(k, v) }
            }))
        }

        if (res.status != HttpStatusCode.Found)
            throw HttpStatusException(res.status, res.bodyAsText())

        val location = res.headers["location"]?.also {
            log.info { "IDToken Response: $it" }
        } ?: throw IllegalStateException("Cannot find 'location' in headers")

        val authCode = urlQueryToMap(location)["code"]?.also {
            cex.authCode = it
        } ?: throw IllegalStateException("No authorization code")

        return authCode
    }

    suspend fun sendTokenRequest(cex: CredentialExchange, authCode: String): TokenResponse {

        val codeVerifier = cex.authRequestCodeVerifier
        val tokenReqUrl = "${cex.authorizationEndpoint}/token"

        val formData = mapOf(
            "grant_type" to "authorization_code",
            "client_id" to cex.didInfo.did,
            "code" to authCode,
            "code_verifier" to codeVerifier,
            "redirect_uri" to cex.authRequest.redirectUri!!,
        )

        WalletActions.log.info { "Send TokenRequest $tokenReqUrl" }
        WalletActions.log.info { "  $formData" }

        val res = http.post(tokenReqUrl) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                formData.forEach { (k, v) -> append(k, v) }
            }))
        }

        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val tokenResponseJson = res.bodyAsText()
        WalletActions.log.info { "TokenResponse: $tokenResponseJson" }

        val tokenResponse = TokenResponse.fromJSONString(tokenResponseJson).also {
            cex.accessToken = SignedJWT.parse(it.accessToken)
        }
        return tokenResponse
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun buildOAuthMetadata(ctx: LoginContext): JsonObject {
        val baseUrl = "$authEndpointUri/${ctx.subjectId}"
        return Json.parseToJsonElement(
            """
            {
              "authorization_endpoint": "$baseUrl/authorize",
              "grant_types_supported": [
                "authorization_code"
              ],
              "id_token_signing_alg_values_supported": [
                "ES256"
              ],
              "id_token_types_supported": [
                "subject_signed_id_token",
                "attester_signed_id_token"
              ],
              "issuer": "$baseUrl",
              "jwks_uri": "$baseUrl/jwks",
              "redirect_uris": [
                "$baseUrl/direct_post"
              ],
              "request_authentication_methods_supported": {
                "authorization_endpoint": [
                  "request_object"
                ]
              },
              "request_object_signing_alg_values_supported": [
                "ES256"
              ],
              "request_parameter_supported": true,
              "request_uri_parameter_supported": true,
              "response_modes_supported": [
                "query"
              ],
              "response_types_supported": [
                "code",
                "vp_token",
                "id_token"
              ],
              "scopes_supported": [
                "openid"
              ],
              "subject_syntax_types_discriminations": [
                "did:key:jwk_jcs-pub",
                "did:ebsi:v1"
              ],
              "subject_syntax_types_supported": [
                "did:key",
                "did:ebsi"
              ],
              "subject_trust_frameworks_supported": [
                "ebsi"
              ],
              "subject_types_supported": [
                "public"
              ],
              "token_endpoint": "$baseUrl/token",
              "token_endpoint_auth_methods_supported": [
                "private_key_jwt"
              ],
              "vp_formats_supported": {
                "jwt_vc": {
                  "alg_values_supported": [
                    "ES256"
                  ]
                },
                "jwt_vc_json": {
                  "alg_values_supported": [
                    "ES256"
                  ]
                },
                "jwt_vp": {
                  "alg_values_supported": [
                    "ES256"
                  ]
                },
                "jwt_vp_json": {
                  "alg_values_supported": [
                    "ES256"
                  ]
                }
              }
            }            
        """.trimIndent()
        ).jsonObject
    }
}
