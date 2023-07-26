package org.nessus.didcomm.service

import id.walt.auditor.Auditor
import id.walt.auditor.VerificationPolicy
import id.walt.auditor.VerificationResult
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.model.W3CVerifiablePresentation
import org.nessus.didcomm.model.toWaltIdType

object NessusAuditorService: ObjectService<NessusAuditorService>() {

    override fun getService() = apply { }

    val auditor get() = Auditor.getService()

    fun verify(vcJson: String, policies: List<VerificationPolicy>): VerificationResult {
        return auditor.verify(vcJson, policies)
    }

    fun verify(vc: W3CVerifiableCredential, policies: List<VerificationPolicy>): VerificationResult {
        return auditor.verify(vc.toWaltIdType(), policies)
    }

    fun verify(vp: W3CVerifiablePresentation, policies: List<VerificationPolicy>): VerificationResult {
        return auditor.verify(vp.toWaltIdType(), policies)
    }
}