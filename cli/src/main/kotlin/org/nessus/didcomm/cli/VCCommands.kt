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

import id.walt.auditor.Auditor
import id.walt.custodian.Custodian
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import id.walt.signatory.Signatory
import org.nessus.didcomm.util.dateTimeNow
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import picocli.CommandLine.Parameters
import java.io.File
import java.time.format.DateTimeFormatter
import java.util.Collections.max

@Command(
    name = "vc",
    description = ["Verifiable credential commands"],
    subcommands = [
        IssueVerifiableCredential::class,
        PresentVerifiableCredential::class,
        VerifyCredentialCommand::class,
        VerificationPolicyCommands::class,
        CredentialTemplateCommands::class,
    ]
)
class VCCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List verifiable credentials"])
    fun listVerifiableCredentials() {
        echo("\nListing verifiable credentials...")
        val vcs = Custodian.getService().listCredentials()
        if (vcs.isNotEmpty()) {
            echo()
            vcs.forEachIndexed { index, vc -> echo("- ${index + 1}: $vc") }
        }
    }
}

@Command(
    name = "issue",
    description = ["Issue a verifiable credential"])
class IssueVerifiableCredential: AbstractBaseCommand() {

    @Option(names = ["-t", "--template"], required = true, description = ["Credential template"])
    var template: String? = null

    @Option(names = ["-i", "--issuer"], required = true, paramLabel = "Did", description = ["DID of the issuer (associated with signing)"])
    var issuerDid: String? = null

    @Option(names = ["-s", "--subject"], required = true, paramLabel = "Did", description = ["DID of the subject (receiver of the credential)"])
    var subjectDid: String? = null

    @Option(names = ["--proof-type"], paramLabel = "[JWT|LD_PROOF]", description = ["Proof type to be used"], defaultValue = "LD_PROOF")
    var proofType: ProofType? = ProofType.LD_PROOF

    @Option(names = ["--proof-purpose"], description = ["Proof purpose to be used"], defaultValue = "assertionMethod")
    var proofPurpose: String = "assertionMethod"

    @Parameters(description = ["The vc output file"])
    var dest: File? = null

    override fun call(): Int {

        echo("Issuing a verifiable credential (using template $template)...")

        val vcStr: String = Signatory.getService().issue(
            template!!, ProofConfig(
                issuerDid = issuerDid!!,
                subjectDid = subjectDid,
                proofType = proofType!!,
                proofPurpose = proofPurpose,
                creator = issuerDid
            ))

        echo("\nResults: ...")
        echo("Issuer $issuerDid issued a $template to Holder $subjectDid")
        echo("Credential document (below, JSON):\n\n$vcStr")

        dest?.run {
            dest!!.writeText(vcStr)
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
    var holderDid: String? = null

    @Option(names = ["-v", "--verifier"], required = true, paramLabel = "Did", description = ["DID of the verifier (recipient of the VP)"])
    var verifierDid: String? = null

    @Option(names = ["-d", "--domain"], description = ["Domain name to be used in the LD proof"])
    var domain: String? = null

    @Option(names = ["-c", "--challenge"], description = ["Challenge to be used in the LD proof"])
    var challenge: String? = null

    @Parameters(index = "0", description = ["The vc input file"])
    var src: File? = null

    @Parameters(index = "1", description = ["The vc output file"], arity = "0..1")
    var dest: File? = null

    override fun call(): Int {
        check(src!!.isFile) { "Not a file: $src" }

        echo("Creating a verifiable presentation for DID $holderDid ...")

        val vpStr = Custodian.getService().createPresentation(
            vcs=listOf(src!!.readText()),
            holderDid=holderDid!!,
            verifierDid=verifierDid!!,
            domain=domain,
            challenge=challenge)

        echo("\nResults: ...")
        echo("Verifiable presentation generated for holder DID: $holderDid")
        echo("Verifiable presentation document (below, JSON):\n\n$vpStr")

        // Storing VP
        if (dest == null) {
            val pattern = DateTimeFormatter.ofPattern("yyMMddHHmmss")
            dest = File("data/vc/presented/vp-${dateTimeNow().format(pattern)}.json")
        }
        dest!!.writeText(vpStr)
        echo("\nVerifiable presentation was saved to file: $dest")
        return 0
    }
}

@Command(
    name = "verify",
    description = ["Verify a credential/presentation"])
class VerifyCredentialCommand: AbstractBaseCommand() {

    @Option(names = ["-p", "--policy"], arity = "1..*", paramLabel = "policy", description = ["Verification policies"])
    var policySpecs: List<String>? = null

    @Parameters(index = "0", description = ["The vc/vp input file"])
    var src: File? = null

    override fun call(): Int {
        check(src!!.isFile) { "Not a file: ${src!!.absoluteFile}" }
        check(policySpecs!!.isNotEmpty()) { "No policies" }

        val policies = policySpecs!!.map {
            val toks = it.split('=')
            when(toks.size) {
                1 -> policyService.getPolicy(toks[0])
                2 -> policyService.getPolicyWithJsonArg(toks[0], toks[1])
                else -> throw IllegalStateException("Unexpected policy spec: $toks")
            }
        }

        echo("Verifying from: $src ...")

        val verificationResult = Auditor.getService().verify(src!!.readText(), policies)

        echo("\nResults ...")
        val maxIdLength = max(policies.map { it.id.length })
        verificationResult.policyResults.forEach { (policy, result) ->
            echo("${policy.padEnd(maxIdLength)} - $result")
        }
        echo("${"Verified".padEnd(maxIdLength)} - ${verificationResult.valid}")
        return if (verificationResult.valid) 0 else 1
    }
}

// Policies ------------------------------------------------------------------------------------------------------------

@Command(
    name = "policy",
    description = ["Verification policy commands"],
)
class VerificationPolicyCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List verification policies"])
    fun listVerificationPolicies() {
        echo("\nListing verification policies ...")
        val maxIdLength = max(policyService.listPolicyInfo().map { (id, _, _, _) -> id.length })
        policyService.listPolicyInfo().forEach { (id, description, argumentType, isMutable) ->
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
class CredentialTemplateCommands: AbstractBaseCommand() {

    @Command(name = "list", description = ["List credential templates"])
    fun listCredentialTemplates() {
        echo("\nListing VC templates ...")
        Signatory.getService().listTemplates().sortedBy { it.name }.forEach { tmpl ->
            echo("${if (tmpl.mutable) "*" else "-"} ${tmpl.name}")
        }
        echo()
        echo("(*) ... custom template")
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
