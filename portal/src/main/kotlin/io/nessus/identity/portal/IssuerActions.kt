package io.nessus.identity.portal

import id.walt.oid4vc.OpenID4VCI
import id.walt.oid4vc.data.CredentialFormat
import id.walt.oid4vc.data.CredentialSupported
import id.walt.oid4vc.data.DisplayProperties
import id.walt.oid4vc.data.GrantType
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.data.SubjectType
import io.nessus.identity.service.ConfigProvider.issuerEndpointUri
import io.nessus.identity.service.ConfigProvider.oauthEndpointUri

object IssuerActions {

    val issuerMetadataUrl = OpenID4VCI.getCIProviderMetadataUrl(issuerEndpointUri)
    val issuerMetadata = buildIssuerMetadata()

    // Private ---------------------------------------------------------------------------------------------------------

    private fun buildIssuerMetadata(): OpenIDProviderMetadata {
        val baseUri = issuerEndpointUri
        val oauthUri = oauthEndpointUri
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