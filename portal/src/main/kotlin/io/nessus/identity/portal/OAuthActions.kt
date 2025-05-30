package io.nessus.identity.portal

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.responses.TokenResponse
import id.walt.oid4vc.util.http
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.request.forms.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.nessus.identity.service.ConfigProvider.oauthEndpointUri
import io.nessus.identity.service.ServiceManager.walletService
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.time.Instant
import java.util.Date

object OAuthActions {

    val log = KotlinLogging.logger {}

    val oauthMetadataUrl = OpenID4VCI.getOpenIdProviderMetadataUrl(oauthEndpointUri)
    val oauthMetadata = buildOAuthMetadata()

    suspend fun handleIDTokenExchange(ctx: HolderContext, queryParams: Map<String, String>) : String {

        // Verify required query params
        for (key in listOf("client_id", "nonce", "state", "redirect_uri", "request_uri")) {
            queryParams[key] ?: throw IllegalStateException("Cannot find $key")
        }

        // The Wallet answers the ID Token Request by providing the id_token in the redirect_uri as instructed by response_mode of direct_post.
        // The id_token must be signed with the DID document's authentication key.

        val authAud = queryParams["client_id"] as String
        val nonce = queryParams["nonce"] as String
        val state = queryParams["state"] as String
        val redirectUri = queryParams["redirect_uri"] as String
        val requestUri = queryParams["request_uri"] as String

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

        val docJson = Json.parseToJsonElement(ctx.didInfo.document).jsonObject
        val authenticationId = (docJson["authentication"] as JsonArray).let { it[0].jsonPrimitive.content }

        val idTokenHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(authenticationId)
            .build()

        val idTokenClaims = JWTClaimsSet.Builder()
            .issuer(ctx.didInfo.did)
            .subject(ctx.didInfo.did)
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
        val idToken = walletService.signWithKey(
            authenticationId,
            idTokenSigningInput
        )

        log.info { "IDToken: $idToken" }
        if (!verifyJwt(SignedJWT.parse(idToken), ctx.didInfo))
            throw IllegalStateException("IDToken signature verification failed")

        // Send IDToken Response --------------------------------------------------------------------------------------
        //

        val formData = mapOf(
            "id_token" to idToken,
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
            ctx.authCode = it
        } ?: throw IllegalStateException("No authorization code")

        return authCode
    }

    suspend fun sendTokenRequest(ctx: HolderContext, authCode: String): TokenResponse {

        val codeVerifier = ctx.authRequestCodeVerifier
        val tokenReqUrl = "${ctx.authorizationServer}/token"

        val formData = mapOf(
            "grant_type" to "authorization_code",
            "client_id" to ctx.didInfo.did,
            "code" to authCode,
            "code_verifier" to codeVerifier,
            "redirect_uri" to oauthEndpointUri,
        )

        HolderActions.log.info { "Send TokenRequest $tokenReqUrl" }
        HolderActions.log.info { "  $formData" }

        val res = http.post(tokenReqUrl) {
            contentType(ContentType.Application.FormUrlEncoded)
            setBody(FormDataContent(Parameters.build {
                formData.forEach { (k, v) -> append(k, v) }
            }))
        }

        if (res.status != HttpStatusCode.OK)
            throw HttpStatusException(res.status, res.bodyAsText())

        val tokenResponseJson = res.bodyAsText()
        HolderActions.log.info { "TokenResponse: $tokenResponseJson" }

        val tokenResponse = TokenResponse.fromJSONString(tokenResponseJson).also {
            ctx.tokenResponse = it
        }

        return tokenResponse
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun buildOAuthMetadata(): JsonObject {
        return Json.parseToJsonElement("""
            {
              "authorization_endpoint": "$oauthEndpointUri/authorize",
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
              "issuer": "$oauthEndpointUri",
              "jwks_uri": "$oauthEndpointUri/jwks",
              "redirect_uris": [
                "$oauthEndpointUri/direct_post"
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
              "token_endpoint": "$oauthEndpointUri/token",
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
        """.trimIndent()).jsonObject
    }
}