package org.nessus.didcomm.service

import id.walt.auditor.ChallengePolicy
import id.walt.auditor.ChallengePolicyArg
import id.walt.auditor.CredentialStatusPolicy
import id.walt.auditor.ExpirationDateAfterPolicy
import id.walt.auditor.IssuedDateBeforePolicy
import id.walt.auditor.PolicyRegistryService
import id.walt.auditor.PresentationDefinitionPolicy
import id.walt.auditor.SignaturePolicy
import id.walt.auditor.ValidFromBeforePolicy
import id.walt.auditor.dynamic.DynamicPolicy
import id.walt.auditor.dynamic.DynamicPolicyArg
import id.walt.model.dif.PresentationDefinition
import id.walt.servicematrix.ServiceProvider
import id.walt.servicematrix.ServiceRegistry

/**
 * A service that manages verification policies
 *
 * For the current set of policies in Walt.Id see
 * https://github.com/tdiesler/waltid-ssikit/blob/master/src/main/kotlin/id/walt/auditor/PolicyRegistry.kt
 */
class NessusPolicyRegistryService: PolicyRegistryService() {

    companion object: ServiceProvider {
        override fun getService() = ServiceRegistry.getService(PolicyRegistryService::class)
    }

    override fun initPolicies() {
        register(SignaturePolicy::class, "Verify by signature")
        register(ChallengePolicy::class, ChallengePolicyArg::class, "Verify challenge")
        register(IssuedDateBeforePolicy::class, "Verify by issuance date")
        register(ValidFromBeforePolicy::class, "Verify by valid from")
        register(ExpirationDateAfterPolicy::class, "Verify by expiration date")
        register(ChallengePolicy::class, ChallengePolicyArg::class, "Verify challenge")
        register(PresentationDefinitionPolicy::class, PresentationDefinition::class, "Verify that verifiable presentation complies with presentation definition")
        register(CredentialStatusPolicy::class, "Verify by credential status")
        register(DynamicPolicy::class, DynamicPolicyArg::class, "Verify credential by 'Rego' policy")
        initSavedPolicies()
    }
}