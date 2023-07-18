package org.nessus.didcomm.service

import id.walt.auditor.Auditor
import id.walt.auditor.VerificationPolicy
import id.walt.auditor.VerificationResult
import id.walt.credentials.w3c.VerifiableCredential

object NessusAuditorService: ObjectService<NessusAuditorService>() {

    override fun getService() = apply { }

    val auditor get() = Auditor.getService()

    fun verify(vcJson: String, policies: List<VerificationPolicy>): VerificationResult {
        return auditor.verify(vcJson, policies)
    }

    fun verify(vc: VerifiableCredential, policies: List<VerificationPolicy>): VerificationResult {
        return auditor.verify(vc, policies)
    }
}