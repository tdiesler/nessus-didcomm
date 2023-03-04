package org.nessus.didcomm.test.vc

import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.dateTimeNow
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.w3c.W3CVerifiableCredential
import org.nessus.didcomm.w3c.W3CVerifiableValidator
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
          "expires": "${dateTimeNow().plusYears(10)}",
          "credentialSubject": {
            "id": "${holderDid.uri}",
            "givenName": "Malathi",
            "familyName": "Hamal",
            "citizenship": "US"
          }
        }""".decodeJson()

        val vc = W3CVerifiableCredential
            .fromPath("/example/vc/malathi-passport-vc.json")
            .merge(mergeData)

        log.info { "Merged: ${vc.encodeJson(true)}" }

        W3CVerifiableValidator.validateSubject(vc)
    }

    @Test
    fun testMissingData() {

        val issuerDid = didService.createDid(DidMethod.KEY)
        val holderDid = didService.createDid(DidMethod.KEY)

        val mergeData = """{
          "id": "urn:uuid:${UUID.randomUUID()}",
          "issuer": "${issuerDid.uri}",
          "issuanceDate" : "${dateTimeNow()}",
          "expires": "${dateTimeNow().plusYears(10)}",
          "credentialSubject": {
            "id": "${holderDid.uri}",
            "givenName": "Malathi",
            "citizenship": "US"
          }
        }""".decodeJson()

        val vc = W3CVerifiableCredential
            .fromPath("/example/vc/malathi-passport-vc.json")
            .merge(mergeData)

        log.info { "Merged: ${vc.encodeJson(true)}" }

        try {
            W3CVerifiableValidator.validateSubject(vc)
        } catch (e: IllegalStateException) {
            e.message shouldBe "Validation errors"
        }
    }
}