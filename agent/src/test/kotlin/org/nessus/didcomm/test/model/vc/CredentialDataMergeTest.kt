package org.nessus.didcomm.test.model.vc

import io.kotest.matchers.shouldBe
import io.kotest.matchers.string.shouldContain
import mu.KotlinLogging
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.W3CVerifiableCredentialHelper
import org.nessus.didcomm.model.W3CVerifiableCredentialValidator
import org.nessus.didcomm.model.validate
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import java.util.UUID

class CredentialDataMergeTest: AbstractAgentTest() {
    private val log = KotlinLogging.logger {}

    @Test
    fun testValidData() {

        val issuerDid = didService.createDid(DidMethod.KEY)
        val holderDid = didService.createDid(DidMethod.KEY)

        val mergeData = """{
          "id": "urn:uuid:${UUID.randomUUID()}",
          "issuer": "${issuerDid.uri}",
          "issuanceDate" : "${dateTimeNow()}",
          "expirationDate": "${dateTimeNow().plusYears(10)}",
          "credentialSubject": {
            "id": "${holderDid.uri}",
            "givenName": "Malathi",
            "familyName": "Hamal",
            "citizenship": "US"
          }
        }""".decodeJson()

        val vc = W3CVerifiableCredentialHelper
            .fromTemplate("Passport", true, mergeData)
            .validate()

        log.info { "Merged: ${vc.encodeJson(true)}" }
    }

    @Test
    fun testMissingData() {

        val issuerDid = didService.createDid(DidMethod.KEY)
        val holderDid = didService.createDid(DidMethod.KEY)

        val mergeData = """{
          "id": "urn:uuid:${UUID.randomUUID()}",
          "issuer": "${issuerDid.uri}",
          "issuanceDate" : "${dateTimeNow()}",
          "expirationDate": "${dateTimeNow().plusYears(10)}",
          "credentialSubject": {
            "id": "${holderDid.uri}",
            "givenName": "Malathi",
            "citizenship": "US"
          }
        }""".decodeJson()

        val vc = W3CVerifiableCredentialHelper.fromTemplate("Passport", true, mergeData)
        log.info { "Merged: ${vc.encodeJson(true)}" }

        val validation = W3CVerifiableCredentialValidator.validateCredential(vc, false)
        validation.isFailure shouldBe true
        "${validation.errors[0]}" shouldContain "credentialSubject.familyName: is missing but it is required"
    }


    @Test
    fun testInvalidCredential() {

        val issuerDid = didService.createDid(DidMethod.KEY)
        val holderDid = didService.createDid(DidMethod.KEY)

        // default issuanceDate
        val mergeData = """{
          "id": "urn:uuid:${UUID.randomUUID()}",
          "issuer": "${issuerDid.uri}",
          "expirationDate": "bad data",
          "credentialSubject": {
            "id": "${holderDid.uri}",
            "givenName": "Malathi",
            "familyName": "Hamal",
            "citizenship": "US"
          }
        }""".decodeJson()

        val vc = W3CVerifiableCredentialHelper.fromTemplate("Passport", true, mergeData)
        log.info { "Merged: ${vc.encodeJson(true)}" }

        val verification = W3CVerifiableCredentialValidator.validateCredential(vc, false)
        "${verification.errors[0]}" shouldContain "Bad 'expirationDate'"
    }
}