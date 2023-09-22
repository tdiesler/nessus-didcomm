package org.nessus.didcomm.service

import id.walt.common.prettyPrint
import id.walt.credentials.w3c.VerifiableCredential
import id.walt.credentials.w3c.templates.VcTemplate
import id.walt.services.context.ContextManager
import id.walt.services.vc.JsonLdCredentialService
import id.walt.services.vc.JwtCredentialService
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import id.walt.signatory.Signatory
import id.walt.signatory.SignatoryConfig
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.util.trimJson

fun VcTemplate.shortString(): String {
    return "${name}[mutable=$mutable]"
}

object NessusSignatoryService: ObjectService<NessusSignatoryService>() {

    @JvmStatic
    fun getService() = apply { }

    private const val VC_GROUP = "signatory"

    private val delegate get() = Signatory.getService()

    val proofConfig get() = signatoryConfig.proofConfig
    val signatoryConfig get() = delegate.configuration as SignatoryConfig
    val templates get() = delegate.listTemplates().sortedBy { it.name }

    fun issue(vc: W3CVerifiableCredential, config: ProofConfig, store: Boolean = false): W3CVerifiableCredential {

        val signedVcJson = when (config.proofType) {
            ProofType.LD_PROOF -> JsonLdCredentialService.getService().sign(vc.toJson(), config)
            ProofType.JWT, ProofType.SD_JWT -> JwtCredentialService.getService().sign(vc.toJson(), config)
        }.trimJson()

        log.info { "Signed Credential: ${signedVcJson.prettyPrint()}" }

        val signedVc = W3CVerifiableCredential.fromJson(signedVcJson)

        if (store) {
            val waltVc = VerifiableCredential.fromJson(signedVcJson)
            val vcId = checkNotNull(waltVc.id) { "No credential Id" }
            ContextManager.vcStore.storeCredential(vcId, waltVc, VC_GROUP)
        }

        return signedVc
    }

    fun findTemplateByAlias(alias: String): VcTemplate? {
        return templates.firstOrNull { it.name.lowercase().startsWith(alias.lowercase()) }
    }
}