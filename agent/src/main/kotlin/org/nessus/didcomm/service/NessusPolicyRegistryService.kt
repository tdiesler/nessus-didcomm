package org.nessus.didcomm.service

import id.walt.auditor.PolicyRegistryService
import id.walt.auditor.dynamic.DynamicPolicy
import id.walt.auditor.dynamic.DynamicPolicyArg
import id.walt.auditor.policies.ChallengePolicy
import id.walt.auditor.policies.ChallengePolicyArg
import id.walt.auditor.policies.JsonSchemaPolicy
import id.walt.auditor.policies.JsonSchemaPolicyArg
import id.walt.auditor.policies.SignaturePolicy
import id.walt.servicematrix.ServiceProvider
import id.walt.servicematrix.ServiceRegistry

/**
 * A service that manages verification policies
 */
class NessusPolicyRegistryService: PolicyRegistryService() {

    companion object: ServiceProvider {
        override fun getService() = ServiceRegistry.getService(PolicyRegistryService::class)
    }

    override fun initPolicies() {
        register(SignaturePolicy::class, "Verify by signature")
        register(JsonSchemaPolicy::class, JsonSchemaPolicyArg::class, "Verify by JSON schema")
        register(ChallengePolicy::class, ChallengePolicyArg::class, "Verify challenge")
        register(DynamicPolicy::class, DynamicPolicyArg::class, "Verify credential by rego policy")

        // register(TrustedSchemaRegistryPolicy::class, "Verify by EBSI Trusted Schema Registry")
        // register(TrustedIssuerDidPolicy::class, "Verify by trusted issuer did")
        // register(TrustedIssuerRegistryPolicy::class, "Verify by trusted EBSI Trusted Issuer Registry record")
        // register(TrustedSubjectDidPolicy::class, "Verify by trusted subject did")
        // register(IssuedDateBeforePolicy::class, "Verify by issuance date")
        // register(ValidFromBeforePolicy::class, "Verify by valid from")
        // register(ExpirationDateAfterPolicy::class, "Verify by expiration date")
        // register(PresentationDefinitionPolicy::class, PresentationDefinition::class, "Verify that verifiable presentation complies with presentation definition")
        // register(CredentialStatusPolicy::class, "Verify by credential status")

        initSavedPolicies()
    }
}