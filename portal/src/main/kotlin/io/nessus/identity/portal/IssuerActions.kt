package io.nessus.identity.portal

import com.nimbusds.jose.JOSEObjectType
import com.nimbusds.jose.JWSAlgorithm
import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.JSONObjectUtils
import com.nimbusds.jwt.JWTClaimsSet
import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.CredentialSupported
import id.walt.oid4vc.data.DisplayProperties
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.data.SubjectType
import id.walt.oid4vc.requests.CredentialRequest
import io.nessus.identity.portal.AuthActions.log
import io.nessus.identity.service.ConfigProvider.authEndpointUri
import io.nessus.identity.service.ConfigProvider.issuerEndpointUri
import io.nessus.identity.service.LoginContext
import io.nessus.identity.service.ServiceProvider.walletService
import io.nessus.identity.service.authenticationId
import kotlinx.serialization.json.Json
import java.time.Instant
import kotlin.uuid.ExperimentalUuidApi
import kotlin.uuid.Uuid

object IssuerActions {

    fun getIssuerMetadataUrl(ctx: LoginContext): String {
        val metadataUrl = OpenID4VCI.getCIProviderMetadataUrl("$issuerEndpointUri/${ctx.subjectId}")
        return metadataUrl
    }

    fun getIssuerMetadata(ctx: LoginContext): OpenIDProviderMetadata {
        val metadata = buildIssuerMetadata(ctx)
        return metadata
    }

    @OptIn(ExperimentalUuidApi::class)
    suspend fun handleCredentialRequest(cex: CredentialExchange, assessToken: SignedJWT, credReq: CredentialRequest) : CredentialResponse {

        val iat = Instant.now()
        val expiresIn: Long = 86400
        val exp = iat.plusSeconds(expiresIn)

        val id = "vc:nessus:conformance#${Uuid.random()}"
        val sub = cex.authRequest.clientId
        val kid = cex.didInfo.authenticationId()

        val credentialJson = """
            {
              "sub": "$sub",
              "jti": "$id",
              "iss": "${cex.did}",
              "iat": ${iat.epochSecond},
              "nbf": ${iat.epochSecond},
              "exp": ${exp.epochSecond},
              "vc": {
                "@context": [
                  "https://www.w3.org/2018/credentials/v1"
                ],
                "credentialSchema": {
                  "id": "https://api-conformance.ebsi.eu/trusted-schemas-registry/v3/schemas/zDpWGUBenmqXzurskry9Nsk6vq2R8thh9VSeoRqguoyMD",
                  "type": "FullJsonSchemaValidator2021"
                },
                "credentialSubject": {
                  "id": "$sub"
                },
                "id": "$id",
                "issuer": "${cex.did}",
                "issued": "$iat",
                "issuanceDate": "$iat",
                "validFrom": "$iat",
                "expirationDate": "$exp",
                "type": [
                  "VerifiableCredential",
                  "VerifiableAttestation",
                  "CTWalletSameAuthorisedInTime"
                ]
              }
            }            
        """.trimIndent()

        val credHeader = JWSHeader.Builder(JWSAlgorithm.ES256)
            .type(JOSEObjectType.JWT)
            .keyID(kid)
            .build()

        val credClaims = JWTClaimsSet.parse(JSONObjectUtils.parse(credentialJson))

        val rawCredentialJwt = SignedJWT(credHeader, credClaims)
        log.info { "Credential Header: ${rawCredentialJwt.header}" }
        log.info { "Credential Claims: ${rawCredentialJwt.jwtClaimsSet}" }

        val signingInput = Json.encodeToString(createFlattenedJwsJson(credHeader, credClaims))
        val signedEncoded = walletService.signWithKey(kid, signingInput)
        val credentialJwt = SignedJWT.parse(signedEncoded)

        log.info { "Credential: $signedEncoded" }
        if (!verifyJwt(credentialJwt, cex.didInfo))
            throw IllegalStateException("Credential signature verification failed")

        val credentialResponse = CredentialResponse(CredentialFormat.jwt_vc, signedEncoded)
        return credentialResponse
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun buildIssuerMetadata(ctx: LoginContext): OpenIDProviderMetadata {
        val baseUri = "$issuerEndpointUri/${ctx.subjectId}"
        val oauthUri = "$authEndpointUri/${ctx.subjectId}"
        val supported = CredentialSupported(
            format = CredentialFormat.jwt_vc,
            display = listOf(DisplayProperties(locale = "en-GB", name = "CTWalletSameAuthorisedInTime")),
            types = listOf("VerifiableCredential", "VerifiableAttestation", "CTWalletSameAuthorisedInTime")
        )
        return OpenIDProviderMetadata.Draft11(
            issuer = baseUri,
            authorizationServer = oauthUri,
            authorizationEndpoint = "$oauthUri/authorize",
            pushedAuthorizationRequestEndpoint = "$oauthUri/par",
            tokenEndpoint = "$oauthUri/token",
            credentialEndpoint = "$baseUri/credential",
            batchCredentialEndpoint = "$baseUri/batch_credential",
            deferredCredentialEndpoint = "$baseUri/credential_deferred",
            jwksUri = "$oauthUri/jwks",
            grantTypesSupported = setOf(GrantType.authorization_code, GrantType.pre_authorized_code),
            requestUriParameterSupported = true,
            subjectTypesSupported = setOf(SubjectType.public),
            credentialIssuer = baseUri,
            responseTypesSupported = setOf(
                "code",
                "vp_token",
                "id_token"
            ),
            idTokenSigningAlgValuesSupported = setOf("ES256"),
            codeChallengeMethodsSupported = listOf("S256"),
            credentialSupported = mapOf("0" to supported),
        )
    }

}
