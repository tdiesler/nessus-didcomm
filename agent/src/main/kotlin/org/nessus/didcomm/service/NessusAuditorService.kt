package org.nessus.didcomm.service

import id.walt.auditor.Auditor
import id.walt.auditor.VerificationPolicy
import id.walt.auditor.VerificationResult
import id.walt.auditor.policies.CredentialStatusPolicy
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.model.W3CVerifiablePresentation
import org.nessus.didcomm.model.toWaltIdType

object NessusAuditorService: ObjectService<NessusAuditorService>() {

    @JvmStatic
    fun getService() = apply { }

    private val delegate get() = Auditor.getService()
    private val policyService get() = NessusPolicyRegistryService.getService()

    val defaultPolicies: List<VerificationPolicy> = listOf(
        policyService.getPolicy(CredentialStatusPolicy::class.simpleName!!)
    )

    fun plusDefaultPolicies(policy: VerificationPolicy) = plusDefaultPolicies(listOf(policy))
    fun plusDefaultPolicies(policies: List<VerificationPolicy>) = defaultPolicies + policies

    fun verify(vc: W3CVerifiableCredential, policies: List<VerificationPolicy>? = null): VerificationResult {
        return delegate.verify(vc.toWaltIdType(), policies ?: defaultPolicies)
    }

    fun verify(vp: W3CVerifiablePresentation, policies: List<VerificationPolicy>? = null): VerificationResult {
        return delegate.verify(vp.toWaltIdType(), policies ?: defaultPolicies)
    }
}