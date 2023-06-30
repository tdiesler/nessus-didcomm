package org.nessus.didcomm.service

import id.walt.common.prettyPrint
import id.walt.credentials.w3c.VerifiableCredential
import id.walt.credentials.w3c.templates.VcTemplate
import id.walt.credentials.w3c.toVerifiableCredential
import id.walt.services.context.ContextManager
import id.walt.services.vc.JsonLdCredentialService
import id.walt.services.vc.JwtCredentialService
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import id.walt.signatory.Signatory
import mu.KotlinLogging
import org.nessus.didcomm.util.trimJson

fun VcTemplate.shortString(): String {
    return "${name}[mutable=$mutable]"
}

object NessusSignatoryService: ObjectService<NessusSignatoryService>() {
    val log = KotlinLogging.logger {}

    override fun getService() = apply { }

    private const val VC_GROUP = "signatory"

    private val delegate get() = Signatory.getService()

    val templates get() = delegate.listTemplates().sortedBy { it.name }

    fun issue(vc: VerifiableCredential, config: ProofConfig, storeCredential: Boolean): VerifiableCredential {

        val signedVcJson = when (config.proofType) {
            ProofType.LD_PROOF -> JsonLdCredentialService.getService().sign(vc.toJson(), config)
            ProofType.JWT, ProofType.SD_JWT -> JwtCredentialService.getService().sign(vc.toJson(), config)
        }.trimJson()

        log.info { "Signed Credential: ${signedVcJson.prettyPrint()}" }

        val signedVc = VerifiableCredential.fromJson(signedVcJson)

        if (storeCredential)
            ContextManager.vcStore.storeCredential(config.credentialId!!, signedVcJson.toVerifiableCredential(), VC_GROUP)

        return signedVc
    }

    fun findTemplateByAlias(alias: String): VcTemplate? {
        return templates.firstOrNull { it.name.lowercase().startsWith(alias.lowercase()) }
    }
}