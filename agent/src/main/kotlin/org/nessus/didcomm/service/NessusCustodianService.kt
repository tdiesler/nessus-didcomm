package org.nessus.didcomm.service

import id.walt.credentials.w3c.PresentableCredential
import id.walt.services.vc.JsonLdCredentialService
import id.walt.services.vc.JwtCredentialService
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.model.W3CVerifiablePresentation
import org.nessus.didcomm.model.toWaltIdType
import org.nessus.didcomm.util.trimJson
import java.time.Instant

object NessusCustodianService: ObjectService<NessusCustodianService>() {

    @JvmStatic
    fun getService() = apply { }

    private val jwtCredentialService = JwtCredentialService.getService()
    private val jsonLdCredentialService = JsonLdCredentialService.getService()

    fun createPresentation(
        vcs: List<W3CVerifiableCredential>,
        holderDid: String,
        verifierDid: String? = null,
        domain: String? = null,
        challenge: String? = null,
        expirationDate: Instant? = null
    ): W3CVerifiablePresentation {
        return createSelectiveDisclosurePresentation(
            vcs.map { PresentableCredential(it.toWaltIdType()) },
            holderDid, verifierDid, domain, challenge, expirationDate
        )
    }

    private fun createSelectiveDisclosurePresentation(
        pcs: List<PresentableCredential>,
        holderDid: String,
        verifierDid: String? = null,
        domain: String? = null,
        challenge: String? = null,
        expirationDate: Instant? = null
    ): W3CVerifiablePresentation {

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
        return W3CVerifiablePresentation.fromJson(vpJson.trimJson())
    }
}