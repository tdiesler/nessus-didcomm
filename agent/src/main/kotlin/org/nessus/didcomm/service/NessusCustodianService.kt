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
        vcs: List<VerifiableCredential>,
        holderDid: String,
        verifierDid: String? = null,
        domain: String? = null,
        challenge: String? = null,
        expirationDate: Instant? = null
    ): VerifiablePresentation {
        return createSelectiveDisclosurePresentation(
            vcs.map { PresentableCredential(it) },
            holderDid, verifierDid, domain, challenge, expirationDate)
    }

    fun createSelectiveDisclosurePresentation(
        pcs: List<PresentableCredential>,
        holderDid: String,
        verifierDid: String? = null,
        domain: String? = null,
        challenge: String? = null,
        expirationDate: Instant? = null
    ): VerifiablePresentation {

        val vpJson = when {
            pcs.all { it.isJwt } -> jwtCredentialService.present(
                pcs,
                holderDid,
                verifierDid,
                challenge,
                expirationDate
            )

            pcs.none { it.isJwt } -> jsonLdCredentialService.present(
                pcs,
                holderDid,
                domain,
                challenge,
                expirationDate
            )

            else -> throw IllegalStateException("All presentable credentials must be of the same proof type.")
        }

        return VerifiablePresentation.fromJson(vpJson.trimJson())
    }
}