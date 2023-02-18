package org.nessus.didcomm.service

import com.beust.klaxon.JsonObject
import com.beust.klaxon.Klaxon
import id.walt.auditor.ChallengePolicy
import id.walt.auditor.ChallengePolicyArg
import id.walt.auditor.CredentialStatusPolicy
import id.walt.auditor.DynamicPolicyFactory
import id.walt.auditor.ExpirationDateAfterPolicy
import id.walt.auditor.IssuedDateBeforePolicy
import id.walt.auditor.ParameterizedVerificationPolicy
import id.walt.auditor.PolicyFactory
import id.walt.auditor.PresentationDefinitionPolicy
import id.walt.auditor.SignaturePolicy
import id.walt.auditor.SimpleVerificationPolicy
import id.walt.auditor.ValidFromBeforePolicy
import id.walt.auditor.VerificationPolicy
import id.walt.auditor.VerificationPolicyMetadata
import id.walt.auditor.dynamic.DynamicPolicy
import id.walt.auditor.dynamic.DynamicPolicyArg
import id.walt.common.resolveContent
import id.walt.model.dif.PresentationDefinition
import id.walt.servicematrix.ServiceProvider
import id.walt.services.context.ContextManager
import id.walt.services.hkvstore.HKVKey
import mu.KotlinLogging
import java.io.StringReader
import kotlin.reflect.KClass

/**
 * A service that manages verification policies
 *
 * For the current set of policies in Walt.Id see
 * https://github.com/tdiesler/waltid-ssikit/blob/master/src/main/kotlin/id/walt/auditor/PolicyRegistry.kt
 */
class VerificationPolicyService: AbstractBaseService() {
    override val implementation get() = serviceImplementation<NessusDidService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = VerificationPolicyService()
        override fun getService() = implementation
        const val SAVED_POLICY_ROOT_KEY = "policies"
    }

    private val policies = mutableMapOf<String, PolicyFactory<*, *>>()
    init {
        initDefaultPolicies()
    }

    fun <P : ParameterizedVerificationPolicy<A>, A : Any> register(
            policy: KClass<P>,
            argType: KClass<A>,
            description: String? = null) {
        policies[policy.simpleName!!] = PolicyFactory(policy, argType, policy.simpleName!!, description)
    }

    fun <P : SimpleVerificationPolicy> register(policy: KClass<P>, description: String? = null) {
        policies[policy.simpleName!!] = PolicyFactory<P, Unit>(policy, null, policy.simpleName!!, description)
    }

    fun registerSavedPolicy(name: String, dynamicPolicyArg: DynamicPolicyArg, immutable: Boolean = false) {
        policies[name] = DynamicPolicyFactory(dynamicPolicyArg, immutable, name = name, description = dynamicPolicyArg.description)
    }

    fun <A : Any> getPolicy(id: String, argument: A? = null) = policies[id]!!.create(argument)
    fun getPolicy(id: String) = getPolicy(id, null)
    fun contains(id: String) = policies.containsKey(id)
    fun listPolicies() = policies.keys
    fun listPolicyInfo() = policies.values.map { p -> VerificationPolicyMetadata(
            p.name,
            p.description,
            p.requiredArgumentType,
            isMutable(p.name)
        )
    }

    fun getPolicyWithJsonArg(id: String, argumentJson: JsonObject?): VerificationPolicy {
        val policyFactory = policies[id] ?: throw IllegalArgumentException("No policy exists with id: $id")
        val argument =
            policyFactory.argType?.let {
                argumentJson?.let {
                    if (policyFactory.argType == JsonObject::class) {
                        argumentJson
                    } else {
                        Klaxon().fromJsonObject(
                            argumentJson,
                            policyFactory.argType!!.java,
                            policyFactory.argType!!
                        )
                    }
                }
            }

        return policyFactory.create(argument)
    }

    fun getPolicyWithJsonArg(id: String, argumentJson: String?): VerificationPolicy {
        return getPolicyWithJsonArg(id, argumentJson?.let { Klaxon().parseJsonObject(StringReader(it)) })
    }

    fun isMutable(name: String): Boolean {
        val polF = policies[name] ?: return false
        return polF is DynamicPolicyFactory && !polF.immutable
    }

    fun createSavedPolicy(name: String, dynPolArg: DynamicPolicyArg, override: Boolean, download: Boolean): Boolean {
        if (!contains(name) || (isMutable(name) && override)) {
            val policyContent = when (download) {
                true -> resolveContent(dynPolArg.policy)
                false -> dynPolArg.policy
            }
            val dynPolArgMod = DynamicPolicyArg(
                name,
                dynPolArg.description,
                dynPolArg.input,
                policyContent,
                dynPolArg.dataPath,
                dynPolArg.policyQuery,
                dynPolArg.policyEngine,
                dynPolArg.applyToVC,
                dynPolArg.applyToVP
            )
            ContextManager.hkvStore.put(HKVKey(SAVED_POLICY_ROOT_KEY, name), Klaxon().toJsonString(dynPolArgMod))
            registerSavedPolicy(name, dynPolArgMod)
            return true
        }
        return false
    }

    fun deleteSavedPolicy(name: String): Boolean {
        if (isMutable(name)) {
            ContextManager.hkvStore.delete(HKVKey(SAVED_POLICY_ROOT_KEY, name))
            policies.remove(name)
            return true
        }
        return false
    }

    private fun initSavedPolicies() {
        ContextManager.hkvStore.listChildKeys(HKVKey(SAVED_POLICY_ROOT_KEY)).forEach {
            registerSavedPolicy(it.name, Klaxon().parse(ContextManager.hkvStore.getAsString(it)!!)!!)
        }
    }

    private fun initDefaultPolicies() {
        register(SignaturePolicy::class, "Verify by signature")
        register(ChallengePolicy::class, ChallengePolicyArg::class, "Verify challenge")
        register(IssuedDateBeforePolicy::class, "Verify by issuance date")
        register(ValidFromBeforePolicy::class, "Verify by valid from")
        register(ExpirationDateAfterPolicy::class, "Verify by expiration date")
        register(ChallengePolicy::class, ChallengePolicyArg::class, "Verify challenge")
        register(PresentationDefinitionPolicy::class, PresentationDefinition::class, "Verify that verifiable presentation complies with presentation definition")
        register(CredentialStatusPolicy::class, "Verify by credential status")
        register(DynamicPolicy::class, DynamicPolicyArg::class, "Verify credential by rego policy")

        initSavedPolicies()
    }
}