package org.nessus.didcomm.service

import id.walt.credentials.w3c.PresentableCredential
import id.walt.credentials.w3c.VerifiableCredential
import id.walt.credentials.w3c.VerifiablePresentation
import id.walt.services.vc.JsonLdCredentialService
import id.walt.services.vc.JwtCredentialService
import mu.KotlinLogging
import org.nessus.didcomm.util.trimJson
import java.time.Instant

object NessusCustodianService: ObjectService<NessusCustodianService>() {
    val log = KotlinLogging.logger {}

    override fun getService() = apply { }

    private val jwtCredentialService = JwtCredentialService.getService()
    private val jsonLdCredentialService = JsonLdCredentialService.getService()

    fun createPresentation(
        vcs: Array<VerifiableCredential>,
        holderDid: String,
        verifierDid: String? = null,
        domain: String? = null,
        challenge: String? = null,
        expirationDate: Instant? = null
    ): VerifiablePresentation {
        return createPresentation(vcs.map { PresentableCredential(it) }, holderDid, verifierDid, domain, challenge, expirationDate)
    }

    fun createPresentation(
        vcs: List<PresentableCredential>,
        holderDid: String,
        verifierDid: String? = null,
        domain: String? = null,
        challenge: String? = null,
        expirationDate: Instant? = null
    ): VerifiablePresentation {

        val vpJson = when {
            vcs.stream().allMatch { it.isJwt } -> jwtCredentialService.present(
                vcs,
                holderDid,
                verifierDid,
                challenge,
                expirationDate
            )

            vcs.stream().noneMatch { it.isJwt } -> jsonLdCredentialService.present(
                vcs,
                holderDid,
                domain,
                challenge,
                expirationDate
            )

            else -> throw IllegalStateException("All verifiable credentials must be of the same proof type.")
        }

        return VerifiablePresentation.fromJson(vpJson.trimJson())
    }
}