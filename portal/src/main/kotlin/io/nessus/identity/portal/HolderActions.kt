package io.nessus.identity.portal

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.data.AuthorizationDetails
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OfferedCredential
import id.walt.oid4vc.data.OpenIDClientMetadata
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.TokenResponse
import id.walt.oid4vc.util.http
import io.github.oshai.kotlinlogging.KotlinLogging
import io.ktor.client.request.*
import io.ktor.client.statement.*
import io.ktor.http.*
import io.nessus.identity.service.ConfigProvider
import io.nessus.identity.service.DidInfo
import io.nessus.identity.service.ServiceManager.walletService
import io.nessus.identity.service.WalletInfo
import kotlinx.serialization.Serializable
import kotlinx.serialization.json.Json
import kotlinx.serialization.json.JsonArray
import kotlinx.serialization.json.JsonPrimitive
import kotlinx.serialization.json.buildJsonObject
import kotlinx.serialization.json.jsonObject
import kotlinx.serialization.json.jsonPrimitive
import java.security.MessageDigest
import java.time.Instant
import java.util.Base64
import java.util.Date
import kotlin.random.Random

object HolderActions {

    val log = KotlinLogging.logger {}

    suspend fun fetchCredentialOfferFromUri(offerUri: String): CredentialOffer {
        log.info { "Fetch CredentialOffer from: $offerUri" }
        val offer = OpenID4VCI.parseAndResolveCredentialOfferRequestUrl(offerUri)
        val offerJson = Json.Default.encodeToString(offer)
        log.info { "  $offerJson" }
        return offer
    }

    suspend fun authorizationRequestFromCredentialOffer(
        ctx: CredentialOfferContext,
        offer: CredentialOffer
    ): AuthorizationRequest {

        val credOfferJson = Json.encodeToString(offer)
        log.info { "Received credential offer: $credOfferJson}" }

        // Get issuer Metadata =========================================================================================
        //
        val issuerMetadata = resolveOpenIDProviderMetadata(offer.credentialIssuer)
        val issuerMetadataJson = Json.encodeToString(issuerMetadata)
        log.info { "Received issuer metadata: $issuerMetadataJson" }

        val draft11Metadata = issuerMetadata as? OpenIDProviderMetadata.Draft11
            ?: throw IllegalStateException("Expected Draft11 metadata, but got ${issuerMetadata::class.simpleName}")

        // Resolve Offered Credential ==================================================================================
        //
        val offeredCredentials = OpenID4VCI.resolveOfferedCredentials(offer, draft11Metadata)
        log.info { "Received offered credentials: ${Json.encodeToString(offeredCredentials)}" }
        if (offeredCredentials.size > 1) log.warn { "Multiple offered credentials, using first" }
        val offeredCredential = offeredCredentials.first()

        ctx.also {
            it.credentialOffer = offer
            it.offeredCredential = offeredCredential
            it.issuerMetadata = issuerMetadata
        }

        // The Wallet will start by requesting access for the desired credential from the Auth Mock (Authorisation Server).
        // The client_metadata.authorization_endpoint is used for the redirect location associated with the vp_token and id_token.
        // If client_metadata fails to provide the required information, the default configuration (openid://) will be used instead.

        val rndBytes = Random.Default.nextBytes(32)
        val codeVerifier = Base64.getUrlEncoder().withoutPadding().encodeToString(rndBytes)
        val sha256 = MessageDigest.getInstance("SHA-256")
        val codeVerifierHash = sha256.digest(codeVerifier.toByteArray(Charsets.US_ASCII))
        val codeChallenge = Base64.getUrlEncoder().withoutPadding().encodeToString(codeVerifierHash)

        ctx.authRequestCodeVerifier = codeVerifier

        val credentialTypes = ctx.offeredCredential.types
            ?: throw IllegalStateException("No credential types")

        // Build AuthRequestUrl
        //
        val oauthConfig = ConfigProvider.requireOAuthConfig()
        val oauthEndpointUri = oauthConfig.endpointUrl

        val authDetails = AuthorizationDetails.fromOfferedCredential(offeredCredential, ctx.credentialIssuerUri)
        val clientMetadata =
            OpenIDClientMetadata(customParameters = mapOf("authorization_endpoint" to JsonPrimitive(oauthEndpointUri)))

        val authRequest = AuthorizationRequest(
            scope = setOf("openid"),
            clientId = ctx.didInfo.did,
            clientMetadata = clientMetadata,
            codeChallenge = codeChallenge,
            codeChallengeMethod = "S256",
            authorizationDetails = listOf(authDetails),
            redirectUri = oauthEndpointUri, // [TODO] what does this do
            issuerState = ctx.issuerState
        ).also {
            ctx.authRequestCodeVerifier = codeVerifier
            ctx.authRequest = it
        }

        log.info { "AuthorizationRequest: ${authRequest.toJSON()}" }
        return authRequest
    }

    suspend fun resolveOpenIDProviderMetadata(issuerUrl: String): OpenIDProviderMetadata {
        val issuerMetadataUrl = "$issuerUrl/.well-known/openid-credential-issuer"
        return http.get(issuerMetadataUrl).bodyAsText().let {

            // [TODO] Remove the trust_framework hack when this is fixed
            // Cannot resolve EBSI issuer metadata
            // https://github.com/walt-id/waltid-identity/issues/1065
            val filteredJson = removeKeyRecursive(it, "trust_framework")

            OpenIDProviderMetadata.fromJSONString(filteredJson)
        }
    }

    suspend fun sendAuthorizationRequest(ctx: CredentialOfferContext, authRequest: AuthorizationRequest): String {

        val authServer = ctx.authorizationServer
        val authReqUrl = URLBuilder("$authServer/authorize").apply {
            authRequest.toHttpParameters().forEach { (k, lst) -> lst.forEach { v -> parameters.append(k, v) } }
        }.buildString()

        log.info { "Send AuthRequest: $authReqUrl" }
        urlQueryToMap(authReqUrl).forEach { (k, v) -> log.info { "  $k=$v" } }

        val res = http.get(authReqUrl)
        if (res.status != HttpStatusCode.Accepted)
            throw HttpStatusException(res.status, res.bodyAsText())

        log.info { "AuthCode: ${ctx.authCode}" }
        return ctx.authCode
    }

    suspend fun sendCredentialRequest(ctx: CredentialOfferContext, tokenResponse: TokenResponse): SignedJWT {

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

        val docJson = Json.parseToJsonElement(ctx.didInfo.document).jsonObject
        val authentication = (docJson["authentication"] as JsonArray).let { it[0].jsonPrimitive.content }

        val credReqHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType("openid4vci-proof+jwt"))
            .keyID(authentication)
            .build()

        val state = ctx.authRequest.state

        val credentialTypes = ctx.offeredCredential.types
            ?: throw IllegalStateException("No credential types")

        val issuerUri = ctx.credentialIssuerUri
        val credentialEndpointUri = ctx.credentialEndpointUri

        val credReqClaims = JWTClaimsSet.Builder()
            .issuer(ctx.didInfo.did)
            .audience(issuerUri)
            .issueTime(iat)
            .expirationTime(exp)
            .claim("nonce", cNonce)
            .claim("state", state)
            .build()

        val credReqInput = Json.encodeToString(
            createFlattenedJwsJson(
                credReqHeader,
                credReqClaims
            )
        )
        val signedCredReqBase64 = walletService.signWithKey(ctx.walletInfo.id, authentication, credReqInput)
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

        log.info { "Send CredentialReq: $credentialEndpointUri" }
        log.info { "  $credReqBody" }

        val res = http.post(credentialEndpointUri) {
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
        log.info { "Credential Header: ${credJwt.header}" }
        log.info { "Credential Claims: ${credJwt.jwtClaimsSet}" }

        val credFormat = CredentialFormat.fromValue(credRes.format)
            ?: throw IllegalStateException("Unsupported credential format: $credRes.format")

        ctx.credFormat = credFormat
        ctx.credJwt = credJwt

        return credJwt
    }

    fun addCredentialToWallet(ctx: CredentialOfferContext, credential: SignedJWT) {
        val walletId = ctx.walletInfo.id
        val format = ctx.credFormat.value
        walletService.addCredential(walletId, format, credential)
    }

    // Private ---------------------------------------------------------------------------------------------------------

}

@Serializable
data class CredentialResponse(
    val format: String,
    val credential: String
)

class CredentialOfferContext {

    lateinit var walletInfo: WalletInfo
    lateinit var didInfo: DidInfo

    lateinit var credentialOffer: CredentialOffer
    lateinit var issuerMetadata: OpenIDProviderMetadata.Draft11
    lateinit var offeredCredential: OfferedCredential

    lateinit var authRequest: AuthorizationRequest
    lateinit var authRequestCodeVerifier: String
    lateinit var authCode: String
    lateinit var tokenResponse: TokenResponse

    lateinit var credFormat: CredentialFormat
    lateinit var credJwt: SignedJWT

    val issuerState
        get() = credentialOffer.grants[GrantType.authorization_code.value]?.issuerState
            ?: throw NoSuchElementException("Missing authorization_code.issuer_state")

    val authorizationServer
        get() = issuerMetadata.authorizationServer
            ?: throw IllegalStateException("Cannot obtain authorization_server from: $issuerMetadata")

    val credentialIssuerUri
        get() = issuerMetadata.credentialIssuer
            ?: throw IllegalStateException("Cannot obtain credential_issuer from: $issuerMetadata")

    val credentialEndpointUri
        get() = issuerMetadata.credentialEndpoint
            ?: throw IllegalStateException("Cannot obtain credential_endpoint from: $issuerMetadata")
}
