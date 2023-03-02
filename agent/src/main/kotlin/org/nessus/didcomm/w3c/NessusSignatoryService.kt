package org.nessus.didcomm.w3c

import id.walt.credentials.w3c.toVerifiableCredential
import id.walt.services.context.ContextManager
import id.walt.services.vc.JsonLdCredentialService
import id.walt.services.vc.JwtCredentialService
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import mu.KotlinLogging
import org.nessus.didcomm.service.ObjectService

object NessusSignatoryService: ObjectService<NessusSignatoryService>() {
    val log = KotlinLogging.logger {}

    override fun getService() = apply { }

    private const val VC_GROUP = "signatory"

    fun issue(vc: W3CVerifiableCredential, config: ProofConfig, storeCredential: Boolean): String {

        log.info { "Signing credential with proof using ${config.proofType.name}..." }
        log.debug { "Signing credential with proof using ${config.proofType.name}, credential is: $vc" }
        val signedVc = when (config.proofType) {
            ProofType.LD_PROOF -> JsonLdCredentialService.getService().sign(vc.toJson(), config)
            ProofType.JWT -> JwtCredentialService.getService().sign(vc.toJson(), config)
        }
        log.debug { "Signed VC is: $signedVc" }

        if (storeCredential) {
            ContextManager.vcStore.storeCredential(config.credentialId!!, signedVc.toVerifiableCredential(), VC_GROUP)
        }

        return signedVc
    }
}