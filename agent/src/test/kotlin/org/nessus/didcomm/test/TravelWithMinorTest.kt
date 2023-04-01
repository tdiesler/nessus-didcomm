package org.nessus.didcomm.test

import id.walt.auditor.VerificationPolicy
import id.walt.common.prettyPrint
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.trimJson
import org.nessus.didcomm.util.unionMap
import java.util.UUID


/**
 * Verifiable Credentials
 * ----------------------
 *
 * Malathi's passport
 *      Establishes identity of the traveling parent
 *
 * Anand's passport
 *      Establishes identity of the minor
 *
 * Anand's Birth Certificate
 *      Establishes relationship to parents and provides link from Rajesh to Anand that qualifies the permission to travel
 *
 * Permission to travel from Rajesh
 *      Grants permission from non-traveling parent for minor to travel
 *
 * https://www.w3.org/TR/vc-use-cases/#international-travel-with-minor-and-upgrade
 */
class TravelWithMinorTest: AbstractAgentTest() {
    private val log = KotlinLogging.logger {}

    @Test
    fun travelWithMinor() {

        // Create the Wallets and Dids

        val govment = Wallet.Builder("Government").build()
        val hospital = Wallet.Builder("Hospital").build()
        val airport = Wallet.Builder("Airport").build()

        val malathi = Wallet.Builder("Malathi").build()
        val rajesh = Wallet.Builder("Rajesh").build()
        val anand = Wallet.Builder("Anand").build()

        val govmentDid = govment.createDid(DidMethod.KEY)
        val hospitalDid = hospital.createDid(DidMethod.KEY)
        val airportDid = airport.createDid(DidMethod.KEY)

        val malathiDid = malathi.createDid(DidMethod.KEY)
        val rajeshDid = rajesh.createDid(DidMethod.KEY)
        val anandDid = anand.createDid(DidMethod.KEY)

        // Government issues passports

        issuePassport(govmentDid, malathi, malathiDid, mapOf(
            "givenName" to "Malathi",
            "familyName" to "Hamal"))

        issuePassport(govmentDid, rajesh, rajeshDid, mapOf(
            "givenName" to "Rajesh",
            "familyName" to "Hamal"))

        // Hospital issues birth certificate

        issueBirthCertificate(hospitalDid, malathi, anandDid, """
            {
              "givenName": "Anand",
              "familyName": "Hamal",
              "birthDate": "2023-01-01T00:00:00Z",
              "parent": [
                {
                  "id": "${malathiDid.uri}",
                  "givenName": "Malathi",
                  "familyName": "Hamal"
                },
                {
                  "id": "${rajeshDid.uri}",
                  "givenName": "Rajesh",
                  "familyName": "Hamal"
                }
              ]
            }
            """.decodeJson())

        // Government issues marriage certificate

        issueMarriageCertificate(govmentDid, malathi, malathiDid, """
            {
              "id": "${malathiDid.uri}",
              "spouse": [
                {
                  "id": "${malathiDid.uri}",
                  "givenName": "Malathi",
                  "familyName": "Hamal"
                },
                {
                  "id": "${rajeshDid.uri}",
                  "givenName": "Rajesh",
                  "familyName": "Hamal"
                }
              ]
            }
            """.decodeJson())

        // Rajesh issues permission to travel

        issueTravelPermission(rajeshDid, malathi, malathiDid, """
            {
                "id": "${malathiDid.uri}",
                "minor": "${anandDid.uri}",
                "location": {
                    "address": {
                        "addressCountry": "CA"
                    }
                }
            }
            """.decodeJson())

        // Malathi presents her Passport at the Airport

        verifyPassportCredential(malathi, malathiDid, airportDid)

        // Malathi presents Anand's Birth Certificate at the Airport

        verifyBirthCertificate(malathi, malathiDid, airportDid)

        // Malathi presents her Marriage Certificate at the Airport

        verifyMarriageCertificate(malathi, malathiDid, airportDid)

        // Malathi presents the TravelPermit at the Airport

        verifyTravelPermission(malathi, rajesh, anand, airportDid)
    }

    private fun issuePassport(issuerDid: Did, holder: Wallet, holderDid: Did, subject: Map<String, Any>): W3CVerifiableCredential {

        val credentialTemplate = """{
            "id": "urn:uuid:${UUID.randomUUID()}",
            "issuer": "${issuerDid.uri}",
            "issuanceDate": "${dateTimeNow()}",
            "expirationDate": "${dateTimeNow().plusYears(10)}",
            "credentialSubject": {
                "id": "${holderDid.uri}",
                "citizenship": "US"
            }
        }""".decodeJson()

        val subjectTemplate = """{
            "credentialSubject": ${subject.encodeJson()}
        }""".decodeJson()

        val mergedData = credentialTemplate.unionMap(subjectTemplate)

        val vc = W3CVerifiableCredential
            .fromTemplate("Passport", true, mergedData)
            .validate()

        val proofConfig = ProofConfig(
            issuerDid = issuerDid.uri,
            subjectDid = holderDid.uri,
            proofPurpose = "assertionMethod",
            proofType = ProofType.LD_PROOF)

        val signedVc = signatory.issue(vc, proofConfig, false)
        holder.addVerifiableCredential(signedVc)

        return signedVc
    }

    private fun issueBirthCertificate(issuerDid: Did, holder: Wallet, subjectDid: Did, subject: Map<String, Any>): W3CVerifiableCredential {

        val credentialTemplate = """{
            "id": "urn:uuid:${UUID.randomUUID()}",
            "issuer": "${issuerDid.uri}",
            "issuanceDate": "${dateTimeNow()}",
            "credentialSubject": {
                "id": "${subjectDid.uri}",
                "birthPlace": {
                    "type": "Hospital",
                    "address": {
                        "type": "US address",
                        "addressLocality": "Denver",
                        "addressRegion": "CO",
                        "postalCode": "80209",
                        "streetAddress": "123 Main St."
                    }
                },
                "citizenship": "US"
            }
        }""".decodeJson()

        val subjectTemplate = """{
            "credentialSubject": ${subject.encodeJson()}
        }""".decodeJson()

        val mergedData = credentialTemplate.unionMap(subjectTemplate)

        val vc = W3CVerifiableCredential
            .fromTemplate("BirthCertificate", true, mergedData)
            .validate()

        val proofConfig = ProofConfig(
            issuerDid = issuerDid.uri,
            subjectDid = subjectDid.uri,
            proofPurpose = "assertionMethod",
            proofType = ProofType.LD_PROOF)

        val signedVc = signatory.issue(vc, proofConfig, false)
        holder.addVerifiableCredential(signedVc)

        return signedVc
    }

    private fun issueMarriageCertificate(issuerDid: Did, holder: Wallet, holderDid: Did, subject: Map<String, Any>): W3CVerifiableCredential {

        val credentialTemplate = """{
            "id": "urn:uuid:${UUID.randomUUID()}",
            "issuer": "${issuerDid.uri}",
            "issuanceDate": "${dateTimeNow()}"
        }""".decodeJson()

        val subjectTemplate = """{
            "credentialSubject": ${subject.encodeJson()}
        }""".decodeJson()

        val mergedData = credentialTemplate.unionMap(subjectTemplate)

        val vc = W3CVerifiableCredential
            .fromTemplate("MarriageCertificate", true, mergedData)
            .validate()

        val proofConfig = ProofConfig(
            issuerDid = issuerDid.uri,
            subjectDid = holderDid.uri,
            proofPurpose = "assertionMethod",
            proofType = ProofType.LD_PROOF)

        val signedVc = signatory.issue(vc, proofConfig, false)
        holder.addVerifiableCredential(signedVc)

        return signedVc
    }


    private fun issueTravelPermission(issuerDid: Did, holder: Wallet, holderDid: Did, subject: Map<String, Any>): W3CVerifiableCredential {

        val credentialTemplate = """{
            "id": "urn:uuid:${UUID.randomUUID()}",
            "issuer": "${issuerDid.uri}",
            "issuanceDate": "${dateTimeNow()}",
            "expirationDate": "${dateTimeNow().plusWeeks(8)}",
            "credentialSubject": {
                "location": {
                    "type": "Country"
                }
            }
        }""".decodeJson()

        val subjectTemplate = """{
            "credentialSubject": ${subject.encodeJson()}
        }""".decodeJson()

        val mergedData = credentialTemplate.unionMap(subjectTemplate)

        val vc = W3CVerifiableCredential
            .fromTemplate("TravelPermission", true, mergedData)
            .validate()

        val proofConfig = ProofConfig(
            issuerDid = issuerDid.uri,
            subjectDid = holderDid.uri,
            proofPurpose = "assertionMethod",
            proofType = ProofType.LD_PROOF)

        val signedVc = signatory.issue(vc, proofConfig, false)
        holder.addVerifiableCredential(signedVc)

        return signedVc
    }

    private fun verifyPassportCredential(holder: Wallet, holderDid: Did, verifierDid: Did) {

        val passportVc = getVerifiableCredential(holder, "Passport")
        val passportVp = createVerifiablePresentation(holderDid, verifierDid, passportVc)

        verifyCredential(passportVp, listOf(
            policyService.getPolicy("JsonSchemaPolicy"),
            policyService.getPolicy("SignaturePolicy")))
    }

    private fun verifyBirthCertificate(holder: Wallet, holderDid: Did, verifierDid: Did) {

        val birthCertificateVc = getVerifiableCredential(holder, "BirthCertificate")
        val birthCertificateVp = createVerifiablePresentation(holderDid, verifierDid, birthCertificateVc)

        verifyCredential(birthCertificateVp, listOf(
            policyService.getPolicy("JsonSchemaPolicy"),
            policyService.getPolicy("SignaturePolicy")))
    }

    private fun verifyMarriageCertificate(holder: Wallet, holderDid: Did, verifierDid: Did) {

        val marriageCertificateVc = getVerifiableCredential(holder, "MarriageCertificate")
        val marriageCertificateVp = createVerifiablePresentation(holderDid, verifierDid, marriageCertificateVc)

        verifyCredential(marriageCertificateVp, listOf(
            policyService.getPolicy("JsonSchemaPolicy"),
            policyService.getPolicy("SignaturePolicy")))
    }

    private fun verifyTravelPermission(malathi: Wallet, rajesh: Wallet, anand: Wallet, verifierDid: Did) {

        val malathiPassportVc = getVerifiableCredential(malathi, "Passport")
        val marriageCertificateVc = getVerifiableCredential(malathi, "MarriageCertificate")
        val travelPermissionVc = getVerifiableCredential(malathi, "TravelPermission")
        val malathiDid = malathi.dids.find { it.method == DidMethod.KEY } as Did
        val malathiId = malathiPassportVc.credentialSubject.id.toString()
        malathiDid.uri shouldBe malathiId

        val rajeshPassportVc = getVerifiableCredential(rajesh, "Passport")
        val rajeshDid = rajesh.dids.find { it.method == DidMethod.KEY } as Did
        val rajeshId = rajeshPassportVc.credentialSubject.id.toString()
        rajeshDid.uri shouldBe rajeshId

        val birthCertificateVc = getVerifiableCredential(malathi, "BirthCertificate")
        val anandDid = anand.dids.find { it.method == DidMethod.KEY } as Did
        val anandId = birthCertificateVc.credentialSubject.id.toString()
        anandDid.uri shouldBe anandId

        // Verify that Malathi is the mother and Rajesh is the father of Anand

        val birthCertificateVp = createVerifiablePresentation(anandDid, verifierDid, birthCertificateVc)
        val birthCertificate = auditor.verify(birthCertificateVp, listOf(
            policyService.getPolicy("JsonSchemaPolicy"),
            policyService.getPolicy("SignaturePolicy"),
            policyService.getPolicyWithJsonArg("DynamicPolicy", """
                {
                    "input": { "motherId": "$malathiId", "fatherId": "$rajeshId" },
                    "policy": "class:nessus/rego/birth-certificate.rego"
                }""".trimJson())))

        birthCertificate.result shouldBe true

        // Verify that Rajesh is married to Malathi

        val marriageCertificateVp = createVerifiablePresentation(malathiDid, verifierDid, marriageCertificateVc)
        val marriageCertificate = auditor.verify(marriageCertificateVp, listOf(
            policyService.getPolicy("JsonSchemaPolicy"),
            policyService.getPolicy("SignaturePolicy"),
            policyService.getPolicyWithJsonArg("DynamicPolicy", """
                {
                    "input": { "firstId": "$malathiId", "secondId": "$rajeshId" },
                    "policy": "class:nessus/rego/marriage-certificate.rego"
                }""".trimJson())))

        marriageCertificate.result shouldBe true

        // Verify that Rajesh has given permission for Anand to travel with Malathi

        val travelPermissionVP = createVerifiablePresentation(malathiDid, verifierDid, travelPermissionVc)
        val travelPermission = auditor.verify(travelPermissionVP, listOf(
            policyService.getPolicy("JsonSchemaPolicy"),
            policyService.getPolicy("SignaturePolicy"),
            policyService.getPolicyWithJsonArg("DynamicPolicy", """
                {
                    "input": { "minorId": "$anandId", "guardianId": "$malathiId" },
                    "policy": "class:nessus/rego/travel-permission.rego"
                }""".trimJson())))

        travelPermission.result shouldBe true

        val combinedVp = custodian.createPresentation(
            vcs = listOf(malathiPassportVc, marriageCertificateVc, birthCertificateVc, travelPermissionVc).toTypedArray(),
            holderDid = malathiDid.uri,
            verifierDid = verifierDid.uri)

        val verification = auditor.verify(combinedVp, listOf(
            policyService.getPolicy("JsonSchemaPolicy"),
            policyService.getPolicy("SignaturePolicy")))

        verification.result shouldBe true

        log.info { combinedVp.prettyPrint() }
    }

    private fun getVerifiableCredential(holder: Wallet, type: String): W3CVerifiableCredential {
        val vc = holder.findVerifiableCredential { vc -> vc.hasType(type) }
        checkNotNull(vc) { "No verifiable credential of type: $type" }
        return vc
    }

    private fun verifyCredential(vp: W3CVerifiableCredential, policies: List<VerificationPolicy>) {
        check(vp.isVerifiablePresentation) { "Not a verifiable presentation: ${vp.shortString()}" }
        val verification = auditor.verify(vp, policies)
        verification.result shouldBe true
    }

    private fun createVerifiablePresentation(holderDid: Did, verifierDid: Did, signedVc: W3CVerifiableCredential): W3CVerifiableCredential {
        return custodian.createPresentation(
            vcs = listOf(signedVc.encodeJson()),
            holderDid = holderDid.uri,
            verifierDid = verifierDid.uri)
    }
}
