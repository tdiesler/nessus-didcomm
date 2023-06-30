package org.nessus.didcomm.service

import id.walt.auditor.Auditor
import id.walt.auditor.VerificationPolicy
import id.walt.auditor.VerificationResult
import id.walt.credentials.w3c.VerifiableCredential

object NessusAuditorService: ObjectService<NessusAuditorService>() {

    override fun getService() = apply { }

    fun verify(vcJson: String, policies: List<VerificationPolicy>): VerificationResult {
        return Auditor.getService().verify(vcJson, policies)
    }

    fun verify(vc: VerifiableCredential, policies: List<VerificationPolicy>): VerificationResult {
        return verify(vc.toJson(), policies)
    }
}