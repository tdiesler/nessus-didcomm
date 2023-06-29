package org.nessus.didcomm.service

import id.walt.auditor.Auditor
import id.walt.auditor.VerificationPolicy
import id.walt.auditor.VerificationResult
import org.nessus.didcomm.model.W3CVerifiableCredential

object NessusAuditorService: ObjectService<NessusAuditorService>() {

    override fun getService() = apply { }

    fun verify(vcJson: String, policies: List<VerificationPolicy>): VerificationResult {
        return Auditor.getService().verify(vcJson, policies)
    }

    fun verify(vc: W3CVerifiableCredential, policies: List<VerificationPolicy>): VerificationResult {
        return verify(vc.toJson(), policies)
    }
}