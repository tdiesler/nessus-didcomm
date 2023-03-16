package org.nessus.didcomm.test.vc

import id.walt.auditor.VerificationPolicy
import id.walt.signatory.ProofConfig
import id.walt.signatory.ProofType
import io.kotest.matchers.shouldBe
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.toUnionMap
import org.nessus.didcomm.util.trimJson
import org.nessus.didcomm.w3c.W3CVerifiableCredential
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
class MalathiTravelTest: AbstractAgentTest() {

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

        issueBirthCertificate(hospitalDid, anand, anandDid, """
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

        val subjectData = """
            {
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
            """.decodeJson()

        issueMarriageCertificate(govmentDid, malathi, malathiDid, subjectData)
        issueMarriageCertificate(govmentDid, rajesh, rajeshDid, subjectData)

        // Rajesh issues permission to travel

        issuePermissionToTravel(rajeshDid, malathi, malathiDid, """
            {
                "agent": "${anandDid.uri}",
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

        verifyBirthCertificate(anand, anandDid, airportDid)

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
                "givenName": "",
                "familyName": "",
                "citizenship": "US"
            }
        }""".decodeJson()

        val subjectTemplate = """{
            "credentialSubject": ${subject.encodeJson()}
        }""".decodeJson()

        val mergedData = credentialTemplate.toUnionMap(subjectTemplate)

        val vc = W3CVerifiableCredential
            .fromTemplate("/nessus/vc-templates/Passport.json", mergedData)
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

    private fun issueBirthCertificate(issuerDid: Did, holder: Wallet, holderDid: Did, subject: Map<String, Any>): W3CVerifiableCredential {

        val credentialTemplate = """{
            "id": "urn:uuid:${UUID.randomUUID()}",
            "issuer": "${issuerDid.uri}",
            "issuanceDate": "${dateTimeNow()}",
            "credentialSubject": {
                "id": "${holderDid.uri}",
                "givenName": "",
                "familyName": "",
                "birthDate": "",
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
                "citizenship": "US",
                "parent": [
                    {
                        "id": "",
                        "givenName": "",
                        "familyName": ""
                    },
                    {
                        "id": "",
                        "givenName": "",
                        "familyName": ""
                    }
                ]
            }
        }""".decodeJson()

        val subjectTemplate = """{
            "credentialSubject": ${subject.encodeJson()}
        }""".decodeJson()

        val mergedData = credentialTemplate.toUnionMap(subjectTemplate)

        val vc = W3CVerifiableCredential
            .fromTemplate("/nessus/vc-templates/BirthCertificate.json", mergedData)
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

    private fun issueMarriageCertificate(issuerDid: Did, holder: Wallet, holderDid: Did, subject: Map<String, Any>): W3CVerifiableCredential {

        val credentialTemplate = """{
            "id": "urn:uuid:${UUID.randomUUID()}",
            "issuer": "${issuerDid.uri}",
            "issuanceDate": "${dateTimeNow()}",
            "credentialSubject": {
                "spouse": [
                    {
                        "id": "",
                        "givenName": "",
                        "familyName": ""
                    },
                    {
                        "id": "",
                        "givenName": "",
                        "familyName": ""
                    }
                ]
            }
        }""".decodeJson()

        val subjectTemplate = """{
            "credentialSubject": ${subject.encodeJson()}
        }""".decodeJson()

        val mergedData = credentialTemplate.toUnionMap(subjectTemplate)

        val vc = W3CVerifiableCredential
            .fromTemplate("/nessus/vc-templates/MarriageCertificate.json", mergedData)
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


    private fun issuePermissionToTravel(issuerDid: Did, holder: Wallet, holderDid: Did, subject: Map<String, Any>): W3CVerifiableCredential {

        val credentialTemplate = """{
            "id": "urn:uuid:${UUID.randomUUID()}",
            "issuer": "${issuerDid.uri}",
            "issuanceDate": "${dateTimeNow()}",
            "expirationDate": "${dateTimeNow().plusWeeks(8)}",
            "credentialSubject": {
                "agent": "",
                "participant": "${holderDid.uri}",
                "location": {
                    "type": "Country",
                    "address": {
                        "addressCountry": ""
                    }
                }
            }
        }""".decodeJson()

        val subjectTemplate = """{
            "credentialSubject": ${subject.encodeJson()}
        }""".decodeJson()

        val mergedData = credentialTemplate.toUnionMap(subjectTemplate)

        val vc = W3CVerifiableCredential
            .fromTemplate("/nessus/vc-templates/TravelPermission.json", mergedData)
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

        val passport = getVerifiableCredential(holder, "Passport")

        verifyCredential(holderDid, verifierDid, passport, listOf(
            policyService.getPolicy("JsonSchemaPolicy"),
            policyService.getPolicy("SignaturePolicy")))
    }

    private fun verifyBirthCertificate(holder: Wallet, holderDid: Did, verifierDid: Did) {

        val birthCertificate = getVerifiableCredential(holder, "BirthCertificate")

        verifyCredential(holderDid, verifierDid, birthCertificate, listOf(
            policyService.getPolicy("JsonSchemaPolicy"),
            policyService.getPolicy("SignaturePolicy")))
    }

    private fun verifyMarriageCertificate(holder: Wallet, holderDid: Did, verifierDid: Did) {

        val marriageCertificate = getVerifiableCredential(holder, "MarriageCertificate")

        verifyCredential(holderDid, verifierDid, marriageCertificate, listOf(
            policyService.getPolicy("JsonSchemaPolicy"),
            policyService.getPolicy("SignaturePolicy")))
    }

    private fun verifyTravelPermission(malathi: Wallet, rajesh: Wallet, anand: Wallet, verifierDid: Did) {

        val malathiPassport = getVerifiableCredential(malathi, "Passport")
        val marriageCertificate = getVerifiableCredential(malathi, "MarriageCertificate")
        val travelPermission = getVerifiableCredential(malathi, "TravelPermission")
        val malathiDid = malathi.dids.find { it.method == DidMethod.KEY } as Did
        val malathiId = malathiPassport.credentialSubject.id.toString()
        malathiDid.uri shouldBe malathiId

        val rajeshPassport = getVerifiableCredential(rajesh, "Passport")
        val rajeshDid = rajesh.dids.find { it.method == DidMethod.KEY } as Did
        val rajeshId = rajeshPassport.credentialSubject.id.toString()
        rajeshDid.uri shouldBe rajeshId

        val birthCertificate = getVerifiableCredential(anand, "BirthCertificate")
        val anandDid = anand.dids.find { it.method == DidMethod.KEY } as Did
        val anandId = birthCertificate.credentialSubject.id.toString()
        anandDid.uri shouldBe anandId

        // Verify that Malathi is the mother and Rajesh is the father of Anand

        val birthCertificateVP = createVerifiablePresentation(anandDid, verifierDid, birthCertificate)
        val birthCertificateResult = auditor.verify(birthCertificateVP, listOf(
            policyService.getPolicy("JsonSchemaPolicy"),
            policyService.getPolicy("SignaturePolicy"),
            policyService.getPolicyWithJsonArg("DynamicPolicy", """
                {
                    "input": { "motherId": "$malathiId", "fatherId": "$rajeshId" },
                    "policy": "class:/rego/birth-certificate.rego"
                }""".trimJson())))

        birthCertificateResult.outcome shouldBe true

        // Verify that Rajesh is married to Malathi

        val marriageCertificateVP = createVerifiablePresentation(malathiDid, verifierDid, marriageCertificate)
        val marriageCertificateResult = auditor.verify(marriageCertificateVP, listOf(
            policyService.getPolicy("JsonSchemaPolicy"),
            policyService.getPolicy("SignaturePolicy"),
            policyService.getPolicyWithJsonArg("DynamicPolicy", """
                {
                    "input": { "firstId": "$malathiId", "secondId": "$rajeshId" },
                    "policy": "class:/rego/marriage-certificate.rego"
                }""".trimJson())))

        marriageCertificateResult.outcome shouldBe true

        // Verify that Rajesh has given permission for Anand to travel with Malathi

        val travelPermissionVP = createVerifiablePresentation(malathiDid, verifierDid, travelPermission)
        val travelPermissionResult = auditor.verify(travelPermissionVP, listOf(
            policyService.getPolicy("JsonSchemaPolicy"),
            policyService.getPolicy("SignaturePolicy"),
            policyService.getPolicyWithJsonArg("DynamicPolicy", """
                {
                    "input": { "agentId": "$anandId", "participantId": "$malathiId" },
                    "policy": "class:/rego/travel-permission.rego"
                }""".trimJson())))

        travelPermissionResult.outcome shouldBe true
    }

    private fun getVerifiableCredential(holder: Wallet, type: String): W3CVerifiableCredential {
        val vc = holder.findVerifiableCredential { vc -> vc.hasType(type) }
        checkNotNull(vc) { "No verifiable credential of type: $type" }
        return vc
    }

    private fun verifyCredential(holderDid: Did, verifierDid: Did, signedVc: W3CVerifiableCredential, policies: List<VerificationPolicy>) {
        val vp = createVerifiablePresentation(holderDid, verifierDid, signedVc)
        val verificationResult = auditor.verify(vp, policies)
        verificationResult.outcome shouldBe true
    }

    private fun createVerifiablePresentation(holderDid: Did, verifierDid: Did, signedVc: W3CVerifiableCredential): String {
        return custodian.createPresentation(
            vcs = listOf(signedVc.encodeJson()),
            holderDid = holderDid.uri,
            verifierDid = verifierDid.uri)
    }
}
