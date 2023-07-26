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

package org.nessus.didcomm.cli.protocol

import id.walt.common.resolveContent
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import org.nessus.didcomm.cli.AbstractBaseCommand
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.model.W3CVerifiableCredentialValidator.validateCredential
import org.nessus.didcomm.service.ISSUE_CREDENTIAL_PROTOCOL_V3
import org.nessus.didcomm.service.PRESENT_PROOF_PROTOCOL_V3
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.toValueMap
import org.nessus.didcomm.util.unionMap
import picocli.CommandLine
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.nio.file.Path
import java.util.Collections.max
import java.util.UUID
import kotlin.io.path.writeText

@Command(
    name = "vc",
    description = ["Verifiable Credential commands"],
    mixinStandardHelpOptions = true,
    subcommands = [
        ProposeCredential::class,
        IssueCredential::class,
        PresentCredential::class,
        VerifyCredentialCommand::class,
        PolicyCommands::class,
        TemplateCommands::class,
    ]
)
class VerifiableCredentialCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List verifiable credentials"], mixinStandardHelpOptions = true)
    fun listVerifiableCredentials(

        @Option(names = ["-w", "--wallet"], paramLabel = "wallet", description = ["Optional wallet alias"])
        walletAlias: String?,

        @Option(names = ["--vc"], paramLabel = "vc", description = ["Select Verifiable Credentials"])
        vcOpt: Boolean?,
    ) {
        val walletVcs = findVerifiableCredentials(walletAlias, vcOpt)
        walletVcs.forEachIndexed { idx, vc ->
            echo("[$idx] - ${vc.type} ${vc.id}")
        }
    }

    @Command(name = "show", description = ["Show a verifiable credential"], mixinStandardHelpOptions = true)
    fun showVerifiableCredential(

        @Option(names = ["-w", "--wallet"], paramLabel = "wallet", description = ["Optional wallet alias"])
        walletAlias: String?,

        @Option(names = ["--vc"], paramLabel = "vc", description = ["Select Verifiable Credentials"])
        vcOpt: Boolean?,

        @CommandLine.Parameters(description = ["The credential alias"])
        alias: String,
    ) {
        val walletVcs = findVerifiableCredentials(walletAlias, vcOpt)
        val predicate = { vc: W3CVerifiableCredential -> vc.id.toString().lowercase().startsWith(alias.lowercase()) }
        val vcp: W3CVerifiableCredential? = alias.toIntOrNull()
            ?. let { idx -> walletVcs[idx] }
            ?: let { walletVcs.firstOrNull { vcp -> predicate(vcp) }}
        vcp?.also {
            echo()
            echo(vcp.encodeJson(true))
        }
    }

    private fun findVerifiableCredentials(walletAlias: String?, vcOpt: Boolean?): List<W3CVerifiableCredential> {
        val ctxWallet = getContextWallet(walletAlias)
        val vcs = ctxWallet.verifiableCredentials
        return vcs.filter { vcOpt == null || vcOpt }
    }
}

@Command(
    name = "propose",
    description = ["Propose a verifiable credential"],
    mixinStandardHelpOptions = true)
class ProposeCredential: AbstractBaseCommand() {

    @Option(names = ["-i", "--issuer"], paramLabel = "Did", description = ["DID of the issuer"])
    var issuerAlias: String? = null

    @Option(names = ["-s", "--subject"], required = true, paramLabel = "Did", description = ["DID of the subject"])
    var subjectAlias: String? = null

    @Option(names = ["-t", "--template"], required = true, description = ["Credential template"])
    var template: String? = null

    @Option(names = ["-d", "--data"], required = true, paramLabel = "json", description = ["Input data that overrides template values"])
    var inputData: String? = null

    @Option(names = ["-o", "--out"], paramLabel = "Path", description = ["Optional vc output path"])
    var dest: Path? = null

    @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
    var verbose: Boolean = false

    override fun call(): Int {
        checkNotNull(template) { "No template" }
        checkNotNull(inputData) { "No input data" }

        val (_, issuerDid) = findWalletAndDidFromAlias(null, issuerAlias!!)
        val (subject, subjectDid) = findWalletAndDidFromAlias(null, subjectAlias!!)
        checkNotNull(issuerDid) { "Cannot find issuer Did: $issuerAlias" }
        checkNotNull(subjectDid) { "Cannot find subject Did: $subjectAlias" }
        checkNotNull(subject) { "Cannot find subject wallet" }

        val pcon = subject.findConnection { c -> c.myDid == subjectDid && c.theirDid == issuerDid }
        check(pcon?.state == ConnectionState.ACTIVE) { "Unexpected connection state: ${pcon?.shortString()}" }

        echo("")

        MessageExchange()
            .withAttachment(MessageExchange.CONNECTION_ATTACHMENT_KEY, pcon!!)
            .withProtocol(ISSUE_CREDENTIAL_PROTOCOL_V3)
            .sendCredentialProposal(
                holder = subject,
                issuerDid = issuerDid,
                template = template!!,
                subjectData = inputData!!.toValueMap(),
                options = """{ 
                    "goal_code": "Issue $template Credential"
                }""".toValueMap()
            )
            .awaitCredentialOffer(subject, issuerDid)
            .awaitIssuedCredential(subject, issuerDid)

        val signedVc = subject.findVerifiableCredentialsByType(template!!)
            .firstOrNull { "${it.credentialSubject?.id}" == subjectDid.uri }
        checkNotNull(signedVc) { "No credential was issued" }

        echo("Holder '${subject.name}' received a '$template' credential")

        val varKey = "${subject.name}.${template}.Vc"
        properties.putVar("$varKey.json", signedVc.toJson())
        properties.putVar(varKey, "${signedVc.id}")
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
    name = "issue",
    description = ["Issue a verifiable credential"],
    mixinStandardHelpOptions = true)
class IssueCredential: AbstractBaseCommand() {

    @Option(names = ["-i", "--issuer"], required = true, paramLabel = "Did", description = ["DID of the issuer"])
    var issuerAlias: String? = null

    @Option(names = ["-s", "--subject"], required = true, paramLabel = "Did", description = ["DID of the subject"])
    var subjectAlias: String? = null

    @Option(names = ["-h", "--holder"], paramLabel = "Did", description = ["DID of the holder"])
    var holderAlias: String? = null

    @Option(names = ["-t", "--template"], required = true, description = ["Credential template"])
    var template: String? = null

    @Option(names = ["-d", "--data"], paramLabel = "json", description = ["Input data that overrides template values"])
    var inputData: String? = null

    @Option(names = ["--proof-type"], paramLabel = "[JWT|LD_PROOF]", description = ["Proof type to be used"], defaultValue = "LD_PROOF")
    var proofType: ProofType? = ProofType.LD_PROOF

    @Option(names = ["--proof-purpose"], description = ["Proof purpose to be used"], defaultValue = "assertionMethod")
    var proofPurpose: String = "assertionMethod"

    @Option(names = ["-o", "--out"], paramLabel = "Path", description = ["Optional vc output path"])
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
        checkNotNull(subjectDid) { "Cannot find subject Did: $subjectAlias" }
        checkNotNull(holderDid) { "Cannot find holder Did: $holderAlias" }

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
        val vc = W3CVerifiableCredential.fromMap(templateC)

        // Validate the credential
        val validationResults = validateCredential(vc, false)
        if (validationResults.isFailure) {
            validationResults.errors.forEach { echo(it) }
            return 1
        }

        val config = ProofConfig(
            issuerDid = issuerDid.uri,
            subjectDid = holderDid.uri,
            proofPurpose = proofPurpose,
            proofType = proofType!!)

        val signedVc = signatory.issue(vc, config)
        holder.addVerifiableCredential(signedVc)

        echo("Issuer '${issuer.name}' issued a '$template' to holder '${holder.name}'")

        val varKey = "${holder.name}.${template}.Vc"
        properties.putVar("$varKey.json", signedVc.toJson())
        properties.putVar(varKey, "${signedVc.id}")
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
    description = ["Present a verifiable credential"],
    mixinStandardHelpOptions = true)
class PresentCredential: AbstractBaseCommand() {

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

    @Option(names = ["-o", "--out"], paramLabel = "Path", description = ["Optional vp output path"])
    var dest: Path? = null

    @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
    var verbose: Boolean = false

    override fun call(): Int {

        val (verifier, verifierDid) = findWalletAndDidFromAlias(null, verifierAlias!!)
        val (prover, proverDid) = findWalletAndDidFromAlias(null, holderAlias!!)
        checkNotNull(verifierDid) { "Cannot find verifier Did: $verifierAlias" }
        checkNotNull(proverDid) { "Cannot find prover Did: $holderAlias" }
        checkNotNull(prover) { "Cannot find prover wallet" }

        val vcs = vcAliases.map { getVcFromAlias(prover, it) }

        val pcon = prover.findConnection { c -> c.myDid == proverDid && c.theirDid == verifierDid }

        // Do the verification through the Present Proof Protocol
        if (pcon != null) {

            check(pcon.state == ConnectionState.ACTIVE) { "Unexpected connection state: ${pcon.shortString()}" }
            MessageExchange()
                .withConnection(pcon)
                .withProtocol(PRESENT_PROOF_PROTOCOL_V3)
                .sendPresentationProposal(
                    prover = prover,
                    verifierDid = verifierDid,
                    vcs = vcs,
                    domain = domain,
                    challenge = challenge,
                    expirationDate = null
                )
                .awaitPresentationRequest(prover, verifierDid)
                .awaitPresentationAck(prover, verifierDid)
                .getMessageExchange()
        }

        // Create the Verifiable Presentation without the Present Proof Protocol
        else {
            checkNotNull(verifier) { "No verifier wallet" }
            val vp = custodian.createPresentation(
                vcs = vcs,
                holderDid = proverDid.uri,
                verifierDid = verifierDid.uri,
                domain = domain,
                challenge = challenge,
                expirationDate = null
            )
            prover.addVerifiablePresentation(vp)
        }

        val templates = vcs.map { it.types.last() }
        val verifierName = verifier?.name ?: pcon?.theirLabel
        echo("Prover '${prover.name}' presents $templates to verifier '${verifierName}'")

        val vp = prover.verifiablePresentations.last()

        val varKey = "${verifierName}.${prover.name}.${templates.joinToString(separator = "")}.Vp"
        properties.putVar("$varKey.json", vp.toJson())
        properties.putVar(varKey, "${vp.id}")
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
    description = ["Verify a credential/presentation"], mixinStandardHelpOptions = true)
class VerifyCredentialCommand: AbstractBaseCommand() {

    @Option(names = ["-p", "--policy"], arity = "1..*", paramLabel = "policy", description = ["Verification policies"])
    var policySpecs: List<String>? = null

    @Option(names = ["--vc"], required = true, description = ["The vc/vp input path/ref"])
    var src: String? = null

    @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
    var verbose: Boolean = false

    override fun call(): Int {
        check(policySpecs!!.isNotEmpty()) { "No policies" }

        val vcp = properties.getVar(src!!)
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

        val verification = auditor.verify(vcp.toJson(), policies)

        val maxIdLength = max(policies.map { it.id.length })
        verification.policyResults.forEach { (policy, result) ->
            echo("${policy.padEnd(maxIdLength)} - $result")
        }
        echo("${"Verified".padEnd(maxIdLength)} - ${verification.result}")
        return if (verification.result) 0 else 1
    }
}

// Policies ------------------------------------------------------------------------------------------------------------

@Command(
    name = "policy",
    description = ["Verification policy commands"],
    mixinStandardHelpOptions = true,
)
class PolicyCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List verification policies"],
        mixinStandardHelpOptions = true)
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

//    @Command(name = "create", description = ["Create a verification policy"], mixinStandardHelpOptions = true)
//    fun createVerificationPolicy() {
//        TODO("createVerificationPolicy")
//    }
//
//    @Command(name = "remove", description = ["Remove a verification policy"], mixinStandardHelpOptions = true)
//    fun removeVerificationPolicy() {
//        TODO("removeVerificationPolicy")
//    }
}

// Template ------------------------------------------------------------------------------------------------------------

@Command(
    name = "template",
    description = ["Credential template commands"],
    mixinStandardHelpOptions = true,
)
class TemplateCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List credential templates"], mixinStandardHelpOptions = true)
    fun listCredentialTemplates() {
        signatory.templates.forEachIndexed { idx, tmpl ->
            echo("[$idx] ${if (tmpl.mutable) "*" else "-"} ${tmpl.name}")
        }
        echo()
        echo("(*) ... custom template")
    }

    @Command(name = "show", description = ["Show a credential template"], mixinStandardHelpOptions = true)
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

//    @Command(name = "export", description = ["Export a credential template"], mixinStandardHelpOptions = true)
//    fun exportCredentialTemplate() {
//        TODO("exportCredentialTemplate")
//    }
//
//    @Command(name = "import", description = ["Import a credential template"], mixinStandardHelpOptions = true)
//    fun importCredentialTemplate() {
//        TODO("importCredentialTemplate")
//    }
//
//    @Command(name = "remove", description = ["Remove a credential template"], mixinStandardHelpOptions = true)
//    fun removeCredentialTemplate() {
//        TODO("removeCredentialTemplate")
//    }
}
