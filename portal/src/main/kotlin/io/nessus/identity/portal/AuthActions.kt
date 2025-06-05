package io.nessus.identity.portal

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.data.GrantDetails
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.dif.InputDescriptor
import id.walt.oid4vc.data.dif.InputDescriptorConstraints
import id.walt.oid4vc.data.dif.InputDescriptorField
import id.walt.oid4vc.data.dif.PresentationDefinition
import id.walt.oid4vc.data.dif.VCFormatDefinition
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.TokenResponse
import id.walt.oid4vc.util.http
import id.walt.w3c.utils.VCFormat
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
     * Handle AuthorizationRequest from remote Holder to this Issuer's Auth Endpoint
     */
    suspend fun handleAuthorizationRequest(cex: CredentialExchange, authReq: AuthorizationRequest): String {

        cex.authRequest = authReq
        cex.issuerMetadata = IssuerActions.getIssuerMetadata(cex)

        // Validate the AuthorizationRequest
        //
        // [TODO] check VC types in authorization_details

        val isVPTokenRequest = authReq.scope.any { it.contains("vp_token") }
        if (isVPTokenRequest) {
            val redirectUrl = sendVPTokenRequest(cex, authReq)
            return redirectUrl
        } else {
            val redirectUrl = sendIDTokenRequest(cex, authReq)
            return redirectUrl
        }
    }

    suspend fun handleAuthorizationRequestCallback(
        cex: CredentialExchange,
        queryParams: Map<String, List<String>>
    ): String {

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

        log.info { "Trigger IDToken Request: $requestUri" }
        var res = http.get(requestUri)
        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val idTokenReq = res.bodyAsText()
        log.info { "IDToken Request: $idTokenReq" }

        val signedJWT = SignedJWT.parse(idTokenReq)
        log.info { "IDToken Request Header: ${signedJWT.header}" }
        log.info { "IDToken Request Claims: ${signedJWT.jwtClaimsSet}" }

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val kid = cex.didInfo.authenticationId()

        val idTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val idTokenClaims = JWTClaimsSet.Builder()
            .issuer(cex.didInfo.did)
            .subject(cex.didInfo.did)
            .audience(authAud)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("nonce", nonce)
            .claim("state", state)
            .build()

        val idTokenJwt = SignedJWT(idTokenHeader, idTokenClaims)
        log.info { "IDToken Header: ${idTokenJwt.header}" }
        log.info { "IDToken Claims: ${idTokenJwt.jwtClaimsSet}" }

        val signingInput = Json.encodeToString(createFlattenedJwsJson(idTokenHeader, idTokenClaims))
        val signedEncoded = walletService.signWithKey(kid, signingInput)

        log.info { "IDToken: $signedEncoded" }
        if (!verifyJwt(SignedJWT.parse(signedEncoded), cex.didInfo))
            throw IllegalStateException("IDToken signature verification failed")

        // Send IDToken  -----------------------------------------------------------------------------------------------
        //

        log.info { "Send IDToken: $redirectUri" }
        val formData = mapOf(
            "id_token" to signedEncoded,
            "state" to state,
        ).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

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

    @OptIn(ExperimentalUuidApi::class)
    fun handleIDTokenResponse(cex: CredentialExchange, postParams: Map<String, List<String>>): String {

        val idToken = postParams["id_token"]?.firstOrNull()
            ?: throw IllegalStateException("No id_token")

        val idTokenJwt = SignedJWT.parse(idToken)
        log.info { "IDToken Header: ${idTokenJwt.header}" }
        log.info { "IDToken Claims: ${idTokenJwt.jwtClaimsSet}" }

        // [TODO] validate IDToken

        cex.authCode = "${Uuid.random()}"

        val authReq = cex.authRequest
        val idTokenRedirect = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("code", cex.authCode)
            authReq.state?.also { state ->
                parameters.append("state", state)
            }
        }.buildString()

        log.info { "IDToken Response $idTokenRedirect" }
        urlQueryToMap(idTokenRedirect).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return idTokenRedirect
    }

    @OptIn(ExperimentalUuidApi::class)
    fun handleVPTokenResponse(cex: CredentialExchange, postParams: Map<String, List<String>>): String {

        val vpToken = postParams["vp_token"]?.firstOrNull()
            ?: throw IllegalStateException("No vp_token")

        val vpTokenJwt = SignedJWT.parse(vpToken)
        log.info { "VPToken Header: ${vpTokenJwt.header}" }
        log.info { "VPToken Claims: ${vpTokenJwt.jwtClaimsSet}" }

        // [TODO] validate VPToken

        cex.authCode = "${Uuid.random()}"

        val authReq = cex.authRequest
        val vpTokenRedirect = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("code", cex.authCode)
            authReq.state?.also { state ->
                parameters.append("state", state)
            }
        }.buildString()

        log.info { "VPToken Response $vpTokenRedirect" }
        urlQueryToMap(vpTokenRedirect).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return vpTokenRedirect
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

        val iat = Instant.now()
        val expiresIn: Long = 86400
        val exp = iat.plusSeconds(expiresIn)

        val nonce = "${Uuid.random()}"
        val authorizationDetails = cex.authRequest.authorizationDetails?.map { it.toJSON() }

        val tokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val tokenClaims = JWTClaimsSet.Builder()
            .issuer(cex.issuerMetadata.credentialIssuer)
            .subject(cex.authRequest.clientId)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("nonce", nonce)
            .claim("authorization_details", authorizationDetails)
            .build()

        val rawTokenJwt = SignedJWT(tokenHeader, tokenClaims)
        log.info { "Token Header: ${rawTokenJwt.header}" }
        log.info { "Token Claims: ${rawTokenJwt.jwtClaimsSet}" }

        val signingInput = Json.encodeToString(createFlattenedJwsJson(tokenHeader, tokenClaims))
        val signedEncoded = walletService.signWithKey(kid, signingInput)
        val accessToken = SignedJWT.parse(signedEncoded)

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
        log.info { "Token Response: ${Json.encodeToString(tokenResponse)}" }
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

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry

        val idTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        @OptIn(ExperimentalUuidApi::class)
        val idTokenClaims = JWTClaimsSet.Builder()
            .issuer(issuerMetadata.credentialIssuer)
            .audience(authReq.clientId)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
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

    @OptIn(ExperimentalUuidApi::class)
    suspend fun sendVPTokenRequest(cex: CredentialExchange, authReq: AuthorizationRequest): String {

        val issuerMetadata = cex.issuerMetadata
        val authorizationEndpoint = cex.authorizationEndpoint

        val keyJwk = cex.didInfo.publicKeyJwk()
        val kid = keyJwk["kid"]?.jsonPrimitive?.content as String

        val iat = Instant.now()
        val exp = iat.plusSeconds(300) // 5 mins expiry
        val scopes = authReq.scope.joinToString(" ")

        val vpTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        fun buildInputDescriptor(): InputDescriptor {
            return InputDescriptor(
                id = "${Uuid.random()}",
                format = mapOf(VCFormat.jwt_vc to VCFormatDefinition(alg = setOf("ES256"))),
                constraints = InputDescriptorConstraints(
                    fields = listOf(
                        InputDescriptorField(
                            path = listOf("$.vc.type"),
                            filter = Json.parseToJsonElement("""{
                                "type": "array",
                                "contains": { "const": "VerifiableAttestation" }
                            }""".trimIndent()).jsonObject
                        )
                    ),
                ),
            )
        }

        val presentationDefinition = PresentationDefinition(
            format = mapOf(
                VCFormat.jwt_vc to VCFormatDefinition(alg = setOf("ES256")),
                VCFormat.jwt_vp to VCFormatDefinition(alg = setOf("ES256"))
            ),
            inputDescriptors = listOf(
                buildInputDescriptor(),
                buildInputDescriptor(),
                buildInputDescriptor(),
            ),
        ).toJSON()

        val presentationDefinitionJson = Json.encodeToString(presentationDefinition)
        log.info { "PresentationDefinition: $presentationDefinitionJson" }

        @OptIn(ExperimentalUuidApi::class)
        val vpTokenClaims = JWTClaimsSet.Builder()
            .issuer(issuerMetadata.credentialIssuer)
            .audience(authReq.clientId)
            .issueTime(Date.from(iat))
            .expirationTime(Date.from(exp))
            .claim("response_type", "vp_token")
            .claim("response_mode", "direct_post")
            .claim("client_id", issuerMetadata.credentialIssuer)
            .claim("redirect_uri", "$authorizationEndpoint/direct_post")
            .claim("scope", scopes)
            .claim("nonce", "${Uuid.random()}")
            .claim("presentation_definition", JSONObjectUtils.parse(presentationDefinitionJson))
            .build()

        val idTokenJwt = SignedJWT(vpTokenHeader, vpTokenClaims)
        log.info { "VPToken Request Header: ${idTokenJwt.header}" }
        log.info { "VPToken Request Claims: ${idTokenJwt.jwtClaimsSet}" }

        val signingInput = Json.encodeToString(createFlattenedJwsJson(vpTokenHeader, vpTokenClaims))
        val signedEncoded = walletService.signWithKey(kid, signingInput)

        val vpTokenRedirectUrl = URLBuilder("${authReq.redirectUri}").apply {
            parameters.append("client_id", authorizationEndpoint)
            parameters.append("response_type", "vp_token")
            parameters.append("response_mode", "direct_post")
            parameters.append("scope", scopes)
            parameters.append("redirect_uri", "$authorizationEndpoint/direct_post")
            parameters.append("request", signedEncoded)
        }.buildString()

        log.info { "VPToken Request $vpTokenRedirectUrl" }
        urlQueryToMap(vpTokenRedirectUrl).also {
            it.forEach { (k, v) -> log.info { "  $k=$v" } }
        }

        return vpTokenRedirectUrl
    }

    suspend fun sendTokenRequest(cex: CredentialExchange, authCode: String): TokenResponse {

        val tokenReqUrl = "${cex.authorizationEndpoint}/token"

        val formData = mutableMapOf(
            "grant_type" to "authorization_code",
            "client_id" to cex.didInfo.did,
            "code" to authCode,
        )
        cex.maybeAuthRequest?.redirectUri?.also {
            formData["redirect_uri"] = it
        }
        cex.authRequestCodeVerifier?.also {
            formData["code_verifier"] = it
        }

        WalletActions.log.info { "Send Token Request $tokenReqUrl" }
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
        WalletActions.log.info { "Token Response: $tokenResponseJson" }

        val tokenResponse = TokenResponse.fromJSONString(tokenResponseJson).also {
            cex.accessToken = SignedJWT.parse(it.accessToken)
        }
        return tokenResponse
    }

    suspend fun sendPreAuthorizedTokenRequest(cex: CredentialExchange, grant: GrantDetails): TokenResponse? {

        val tokenReqUrl = "${cex.authorizationEndpoint}/token"

        val formData = mapOf(
            "grant_type" to "urn:ietf:params:oauth:grant-type:pre-authorized_code",
            "pre-authorized_code" to grant.preAuthorizedCode as String,
            "user_pin" to "5797", // [TODO] replace with actual PIN
        )

        WalletActions.log.info { "Send Token Request $tokenReqUrl" }
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
        WalletActions.log.info { "Token Response: $tokenResponseJson" }

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
