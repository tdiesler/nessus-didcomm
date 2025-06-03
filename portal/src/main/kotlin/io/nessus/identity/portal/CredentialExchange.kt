package io.nessus.identity.portal

import com.nimbusds.jwt.SignedJWT
import id.walt.oid4vc.data.CredentialOffer
import id.walt.oid4vc.data.OfferedCredential
import id.walt.oid4vc.data.OpenIDProviderMetadata
import id.walt.oid4vc.requests.AuthorizationRequest
import id.walt.oid4vc.responses.CredentialResponse
import io.nessus.identity.service.LoginContext
import java.time.Instant

class CredentialExchange(ctx: LoginContext) : LoginContext(ctx.authToken, ctx.walletInfo, ctx.didInfo) {

    lateinit var issuerMetadata: OpenIDProviderMetadata

    lateinit var authRequest: AuthorizationRequest
    lateinit var authRequestCodeVerifier: String
    lateinit var authCode: String
    lateinit var accessToken: SignedJWT

    lateinit var credentialOffer: CredentialOffer
    lateinit var offeredCredential: OfferedCredential

    lateinit var credResponse: CredentialResponse

    val authorizationEndpoint
        get() = (issuerMetadata as? OpenIDProviderMetadata.Draft11)?.authorizationServer
            ?: (issuerMetadata as? OpenIDProviderMetadata.Draft13)?.authorizationEndpoint
            ?: throw IllegalStateException("Cannot obtain authorization_server from: $issuerMetadata")

    init {
        registry[subjectId] = this
    }

    companion object {

        // A global registry that allows us to resolve a CredentialExchange from subjectId
        private val registry = mutableMapOf<String, CredentialExchange>()

        fun resolveCredentialExchange(subId: String): CredentialExchange? {
            return registry[subId]
        }

        fun requireCredentialExchange(subId: String): CredentialExchange {
            return resolveCredentialExchange(subId)
                ?: throw IllegalStateException("Cannot resolve CredentialExchange for: $subId")
        }
    }

    override fun close() {
        registry.remove(subjectId)
        super.close()
    }

    fun validateBearerToken(bearerToken: SignedJWT) {

        val claims = bearerToken.jwtClaimsSet
        val exp = claims.expirationTime?.toInstant()
        if (exp == null || exp.isBefore(Instant.now()))
            throw IllegalStateException("Token expired")

        // [TODO] consider other access token checks
    }
}