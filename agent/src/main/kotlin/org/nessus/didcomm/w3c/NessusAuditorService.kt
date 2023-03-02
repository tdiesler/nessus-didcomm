package org.nessus.didcomm.w3c

import id.walt.auditor.Auditor
import id.walt.auditor.VerificationPolicy
import id.walt.auditor.VerificationResult
import org.nessus.didcomm.service.ObjectService

object NessusAuditorService: ObjectService<NessusAuditorService>() {

    override fun getService() = apply { }

    fun verify(vcJson: String, policies: List<VerificationPolicy>): VerificationResult {
        val auditor = Auditor.getService()
        return auditor.verify(vcJson, policies)
    }
}