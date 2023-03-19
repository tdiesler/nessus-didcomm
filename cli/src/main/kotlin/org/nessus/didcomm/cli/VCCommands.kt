/*-
 * #%L
 * Nessus DIDComm :: CLI
 * %%
 * Copyright (C) 2022 - 2023 Nessus
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */

package org.nessus.didcomm.cli

import id.walt.common.resolveContent
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.trimJson
import org.nessus.didcomm.util.unionMap
import org.nessus.didcomm.w3c.W3CVerifiableCredential
import org.nessus.didcomm.w3c.W3CVerifiableCredentialValidator.validateCredential
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.nio.file.Path
import java.util.Collections.max
import java.util.UUID
import kotlin.io.path.writeText

@Command(
    name = "vc",
    description = ["Verifiable credential commands"],
    subcommands = [
        IssueVerifiableCredential::class,
        PresentVerifiableCredential::class,
        VerifyCredentialCommand::class,
        PolicyCommands::class,
        TemplateCommands::class,
    ]
)
class VCCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List verifiable credentials"])
    fun listVerifiableCredentials(

        @Option(names = ["--wallet"], paramLabel = "wallet", description = ["Optional wallet alias"])
        walletAlias: String?,

        @Option(names = ["--vc"], paramLabel = "vc", description = ["Select Verifiable Credentials"])
        vcOpt: Boolean?,

        @Option(names = ["--vp"], paramLabel = "vp", description = ["Select Verifiable Presentations"])
        vpOpt: Boolean?,
    ) {
        val sortedVcps = sortedVcps(walletAlias, vcOpt, vpOpt)
        sortedVcps.forEachIndexed { idx, vcp ->
            echo("[$idx] - ${vcp.types} ${vcp.id}")
        }
    }

    @Command(name = "show", description = ["Show a verifiable credential"])
    fun showVerifiableCredential(

        @Option(names = ["--wallet"], paramLabel = "wallet", description = ["Optional wallet alias"])
        walletAlias: String?,

        @Option(names = ["--vc"], paramLabel = "vc", description = ["Select Verifiable Credentials"])
        vcOpt: Boolean?,

        @Option(names = ["--vp"], paramLabel = "vp", description = ["Select Verifiable Presentations"])
        vpOpt: Boolean?,

        @CommandLine.Parameters(description = ["The credential alias"])
        alias: String,
    ) {
        val sortedVcps = sortedVcps(walletAlias, vcOpt, vpOpt)
        val predicate = { vc: W3CVerifiableCredential -> vc.id.toString().lowercase().startsWith(alias.lowercase()) }
        val vcp = alias.toIntOrNull()
            ?. let { idx -> sortedVcps[idx] }
            ?: let { sortedVcps.firstOrNull { vcp -> predicate(vcp) }}
        vcp?.also {
            echo()
            echo(vcp.encodeJson(true))
        }
    }

    private fun sortedVcps(walletAlias: String?, vcOpt: Boolean?, vpOpt: Boolean?): List<W3CVerifiableCredential> {
        val ctxWallet = getContextWallet(walletAlias)
        val vcs = ctxWallet.verifiableCredentials.filter { it.isVerifiableCredential }
        val vps = ctxWallet.verifiableCredentials.filter { it.isVerifiablePresentation }
        return vcs.filter { vcOpt == null || vcOpt } + vps.filter { vpOpt == null || vpOpt }
    }
}

@Command(
    name = "issue",
    description = ["Issue a verifiable credential"])
class IssueVerifiableCredential: AbstractBaseCommand() {

    @Option(names = ["-t", "--template"], required = true, description = ["Credential template"])
    var template: String? = null

    @Option(names = ["-i", "--issuer"], required = true, paramLabel = "Did", description = ["DID of the issuer"])
    var issuerAlias: String? = null

    @Option(names = ["-s", "--subject"], required = true, paramLabel = "Did", description = ["DID of the subject"])
    var subjectAlias: String? = null

    @Option(names = ["-h", "--holder"], paramLabel = "Did", description = ["DID of the holder"])
    var holderAlias: String? = null

    @Option(names = ["-d", "--data"], paramLabel = "json", description = ["Input data that overrides template values"])
    var inputData: String? = null

    @Option(names = ["--proof-type"], paramLabel = "[JWT|LD_PROOF]", description = ["Proof type to be used"], defaultValue = "LD_PROOF")
    var proofType: ProofType? = ProofType.LD_PROOF

    @Option(names = ["--proof-purpose"], description = ["Proof purpose to be used"], defaultValue = "assertionMethod")
    var proofPurpose: String = "assertionMethod"

    @Option(names = ["-o", "--out"], paramLabel = "Path", description = ["The vc output path"])
    var dest: Path? = null

    @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
    var verbose: Boolean = false

    override fun call(): Int {

        if (holderAlias == null)
            holderAlias = subjectAlias

        val (issuer, issuerDid) = findWalletAndDidFromAlias(null, issuerAlias!!)
        val (subject, subjectDid) = findWalletAndDidFromAlias(null, subjectAlias!!)
        val (holder, holderDid) = findWalletAndDidFromAlias(null, holderAlias!!)

        checkNotNull(issuer) { "Cannot find issuer wallet" }
        checkNotNull(subject) { "Cannot find subject wallet" }
        checkNotNull(holder) { "Cannot find holder wallet" }

        checkNotNull(issuerDid) { "Cannot find issuer Did: $issuerAlias" }
        checkNotNull(subjectDid) { "Cannot find issuer Did: $subjectAlias" }
        checkNotNull(holderDid) { "Cannot find issuer Did: $holderAlias" }

        echo("")

        // The raw template data with no values
        val templateA = W3CVerifiableCredential.loadTemplate(template!!)

        // Add values required by all templates
        val templateB = templateA.unionMap("""{
            "id": "urn:uuid:${UUID.randomUUID()}",
            "issuer": "${issuerDid.uri}",
            "issuanceDate": "${dateTimeNow()}",
            "credentialSubject": {
                "id": "${subjectDid.uri}"
            }
        }""".decodeJson())

        // Merge with input data
        val templateC = inputData?.let {
            templateB.unionMap(inputData!!.decodeJson())
        } ?: templateB

        // Create the verifiable credential
        val vc = W3CVerifiableCredential.fromJson(templateC)

        // Validate the credential
        val validationResults = validateCredential(vc, false)
        if (validationResults.isFailure) {
            validationResults.errors.forEach { echo(it) }
            return 1
        }

        val proofConfig = ProofConfig(
            issuerDid = issuerDid.uri,
            subjectDid = holderDid.uri,
            proofPurpose = proofPurpose,
            proofType = proofType!!)

        val signedVc = signatory.issue(vc, proofConfig, false)
        holder.addVerifiableCredential(signedVc)

        echo("Issuer '${issuer.name}' issued a '$template' to holder '${holder.name}'")

        val varKey = "${holder.name}.${template}.Vc"
        cliService.putVar("$varKey.json", signedVc.encodeJson())
        cliService.putVar(varKey, "${signedVc.id}")
        echo("$varKey=${signedVc.id}")

        if (verbose)
            echo("\n$varKey.json=${signedVc.encodeJson(true)}")

        dest?.run {
            dest!!.writeText(signedVc.encodeJson(true))
            echo("\nSaved credential to file: $dest")
        }

        return 0
    }
}

@Command(
    name = "present",
    description = ["Present a verifiable credential"])
class PresentVerifiableCredential: AbstractBaseCommand() {

    @Option(names = ["-h", "--holder"], required = true, paramLabel = "Did", description = ["DID of the holder (owner of the VC)"])
    var holderAlias: String? = null

    @Option(names = ["-y", "--verifier"], required = true, paramLabel = "Did", description = ["DID of the verifier (recipient of the VP)"])
    var verifierAlias: String? = null

    @Option(names = ["-d", "--domain"], description = ["Domain name to be used in the LD proof"])
    var domain: String? = null

    @Option(names = ["-c", "--challenge"], description = ["Challenge to be used in the LD proof"])
    var challenge: String? = null

    @Option(names = ["--vc"], required = true, arity = "1..*", paramLabel = "vcs", description = ["The vc input path/ref"])
    var vcAliases: List<String> = mutableListOf()

    @Option(names = ["-o", "--out"], paramLabel = "Path", description = ["The vp output path"])
    var dest: Path? = null

    @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
    var verbose: Boolean = false

    override fun call(): Int {

        val (holder, holderDid) = findWalletAndDidFromAlias(null, holderAlias!!)
        val (verifier, verifierDid) = findWalletAndDidFromAlias(null, verifierAlias!!)

        checkNotNull(holder) { "Cannot find holder wallet" }
        checkNotNull(holderDid) { "Cannot find holder Did: $holderAlias" }

        checkNotNull(verifier) { "Cannot find verifier wallet" }
        checkNotNull(verifierDid) { "Cannot find verifier Did: $verifierAlias" }

        val vcs = vcAliases.map {
            val vc = getVcpFromAlias(holder, it)
            checkNotNull(vc) { "Cannot find vc in holder wallet: $it" }
        }

        val vpJson = custodian.createPresentation(
            vcs = vcs.map { it.encodeJson() },
            holderDid = holderDid.uri,
            verifierDid = verifierDid.uri,
            challenge= challenge,
            domain = domain).trimJson()

        val vp = W3CVerifiableCredential.fromJson(vpJson)
        verifier.addVerifiableCredential(vp)

        val templates = vcs.map { it.types.last() }
        echo("Holder '${holder.name}' presents $templates to verifier '${verifier.name}'")

        val varKey = "${verifier.name}.${holder.name}.${templates.joinToString(separator = "")}.Vp"
        cliService.putVar("$varKey.json", vpJson)
        cliService.putVar(varKey, "${vp.id}")
        echo("$varKey=${vp.id}")

        if (verbose)
            echo("\n$varKey.json=${vp.encodeJson(true)}")

        dest?.run {
            dest!!.writeText(vp.encodeJson(true))
            echo("\nSaved presentation to file: $dest")
        }

        return 0
    }
}

@Command(
    name = "verify",
    description = ["Verify a credential/presentation"])
class VerifyCredentialCommand: AbstractBaseCommand() {

    @Option(names = ["-p", "--policy"], arity = "1..*", paramLabel = "policy", description = ["Verification policies"])
    var policySpecs: List<String>? = null

    @Option(names = ["--vc"], required = true, description = ["The vc/vp input path/ref"])
    var src: String? = null

    @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
    var verbose: Boolean = false

    override fun call(): Int {
        check(policySpecs!!.isNotEmpty()) { "No policies" }

        val vcp = cliService.getVar(src!!)
            ?.let { W3CVerifiableCredential.fromJson(it) }
            ?: resolveContent(src!!).let { W3CVerifiableCredential.fromJson(it) }

        val policies = policySpecs!!.map {
            val toks = it.split('=')
            when(toks.size) {
                1 -> policyService.getPolicy(toks[0])
                2 -> policyService.getPolicyWithJsonArg(toks[0], toks[1])
                else -> throw IllegalStateException("Unexpected policy spec: $toks")
            }
        }

        echo("Verifying: $src ...")
        if (verbose)
            echo("\n${vcp.encodeJson(true)}")
        echo("")

        val verificationResult = auditor.verify(vcp.encodeJson(), policies)

        val maxIdLength = max(policies.map { it.id.length })
        verificationResult.policyResults.forEach { (policy, result) ->
            echo("${policy.padEnd(maxIdLength)} - $result")
        }
        echo("${"Verified".padEnd(maxIdLength)} - ${verificationResult.outcome}")
        return if (verificationResult.outcome) 0 else 1
    }
}

// Policies ------------------------------------------------------------------------------------------------------------

@Command(
    name = "policy",
    description = ["Verification policy commands"],
)
class PolicyCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List verification policies"])
    fun listVerificationPolicies() {
        val maxIdLength = max(policyService.listPolicyInfo().map { (id, _, _, _) -> id.length })
        policyService.listPolicyInfo().sortedBy { it.id }.forEach { (id, description, argumentType, isMutable) ->
            echo("${if (isMutable) "*" else "-"} %s %s %s".format(
                id.padEnd(maxIdLength),
                description ?: "No description",
                if (argumentType == "None") "" else "[$argumentType]"))
        }
        echo()
        echo("(*) ... mutable dynamic policy")
    }

//    @Command(name = "create", description = ["Create a verification policy"])
//    fun createVerificationPolicy() {
//        TODO("createVerificationPolicy")
//    }
//
//    @Command(name = "remove", description = ["Remove a verification policy"])
//    fun removeVerificationPolicy() {
//        TODO("removeVerificationPolicy")
//    }
}

// Template ------------------------------------------------------------------------------------------------------------

@Command(
    name = "template",
    description = ["Credential template commands"],
)
class TemplateCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List credential templates"])
    fun listCredentialTemplates() {
        signatory.templates.forEachIndexed { idx, tmpl ->
            echo("[$idx] ${if (tmpl.mutable) "*" else "-"} ${tmpl.name}")
        }
        echo()
        echo("(*) ... custom template")
    }

    @Command(name = "show", description = ["Show a credential template"])
    fun showCredentialTemplate(
        @CommandLine.Parameters(description = ["The template alias"])
        alias: String,

        @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
        verbose: Boolean
    ) {
        // Did alias as an index into the context wallet did list
        if (alias.toIntOrNull() != null) {
            val idx = alias.toInt()
            signatory.templates[idx]
        } else {
            signatory.findTemplateByAlias(alias)
        }?.also { tmpl ->
            val vc = W3CVerifiableCredential.loadTemplate(tmpl.name, false)
            if (verbose) {
                echo(vc.encodeJson(true))
            } else {
                val subject = vc["credentialSubject"] as Map<*, *>
                echo(subject.encodeJson(true))
            }
        }
    }

//    @Command(name = "export", description = ["Export a credential template"])
//    fun exportCredentialTemplate() {
//        TODO("exportCredentialTemplate")
//    }
//
//    @Command(name = "import", description = ["Import a credential template"])
//    fun importCredentialTemplate() {
//        TODO("importCredentialTemplate")
//    }
//
//    @Command(name = "remove", description = ["Remove a credential template"])
//    fun removeCredentialTemplate() {
//        TODO("removeCredentialTemplate")
//    }
}
