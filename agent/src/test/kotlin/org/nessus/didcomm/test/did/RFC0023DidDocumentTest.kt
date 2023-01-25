/*-
 * #%L
 * Nessus DIDComm :: Core
 * %%
 * Copyright (C) 2022 Nessus
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
package org.nessus.didcomm.test.did

import id.walt.common.prettyPrint
import id.walt.crypto.KeyAlgorithm
import mu.KotlinLogging
import org.junit.jupiter.api.Test
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.service.RFC0023DidDocument
import org.nessus.didcomm.test.AbstractDidCommTest
import org.nessus.didcomm.util.decodeBase64Url
import org.nessus.didcomm.util.decodeBase64UrlStr
import org.nessus.didcomm.util.decodeHex
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.selectJson
import org.nessus.didcomm.util.trimJson
import org.nessus.didcomm.wallet.DidMethod
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class RFC0023DidDocumentTest: AbstractDidCommTest() {
    val log = KotlinLogging.logger {}

    @Test
    fun diddoc_attach_parse_verify() {

        // did_doc~attach
        val attachment = """
        {
            "@id": "9b88f208-6570-4374-b023-d0493ae96693",
            "data": {
              "base64": "eyJAY29udGV4dCI6ICJodHRwczovL3czaWQub3JnL2RpZC92MSIsICJpZCI6ICJkaWQ6c292OkREM2RydVE0dEZRSFpqY3dnbjNLU2MiLCAicHVibGljS2V5IjogW3siaWQiOiAiZGlkOnNvdjpERDNkcnVRNHRGUUhaamN3Z24zS1NjIzEiLCAidHlwZSI6ICJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCIsICJjb250cm9sbGVyIjogImRpZDpzb3Y6REQzZHJ1UTR0RlFIWmpjd2duM0tTYyIsICJwdWJsaWNLZXlCYXNlNTgiOiAiN2V1aUpwQ2FyNUFaTW9YR3NwZFNCaEpCS3pqOFFaTTVVM1FTU1NoOExBQTUifV0sICJhdXRoZW50aWNhdGlvbiI6IFt7InR5cGUiOiAiRWQyNTUxOVNpZ25hdHVyZUF1dGhlbnRpY2F0aW9uMjAxOCIsICJwdWJsaWNLZXkiOiAiZGlkOnNvdjpERDNkcnVRNHRGUUhaamN3Z24zS1NjIzEifV0sICJzZXJ2aWNlIjogW3siaWQiOiAiZGlkOnNvdjpERDNkcnVRNHRGUUhaamN3Z24zS1NjO2luZHkiLCAidHlwZSI6ICJJbmR5QWdlbnQiLCAicHJpb3JpdHkiOiAwLCAicmVjaXBpZW50S2V5cyI6IFsiN2V1aUpwQ2FyNUFaTW9YR3NwZFNCaEpCS3pqOFFaTTVVM1FTU1NoOExBQTUiXSwgInNlcnZpY2VFbmRwb2ludCI6ICJodHRwOi8vbG9jYWxob3N0OjgwMzAifV19",
              "jws": {
                "header": {
                  "kid": "did:key:z6Mkm7Aku4T2Bcf2UJMyZPbH2nrB9ZzypSbSA4KNGif9FNwT"
                },
                "protected": "eyJhbGciOiAiRWREU0EiLCAia2lkIjogImRpZDprZXk6ejZNa203QWt1NFQyQmNmMlVKTXlaUGJIMm5yQjlaenlwU2JTQTRLTkdpZjlGTndUIiwgImp3ayI6IHsia3R5IjogIk9LUCIsICJjcnYiOiAiRWQyNTUxOSIsICJ4IjogIll0dzJucmdwRVdCekVlUTJKMUpnMVliRnRwU3Boc3h2dnU1UVNLaXU5M28iLCAia2lkIjogImRpZDprZXk6ejZNa203QWt1NFQyQmNmMlVKTXlaUGJIMm5yQjlaenlwU2JTQTRLTkdpZjlGTndUIn19",
                "signature": "Vs92nQ34labyLy1Q-c1ttSBEgv0P-z0ns7heUQXzLpfGfCffHogdsEKWO0pSxxt8lIVWYTYzNWXhIPM8tumAAg"
              }
            },
            "mime-type": "application/json"
          }
          """.trimJson()

        val didDocument64 = attachment.selectJson("data.base64") as String
        val didDocument = didDocument64.decodeBase64UrlStr() // Contains json whitespace
        log.info { "Did Document: ${didDocument.prettyPrint()}" }

        val expDidDocument = """
        {
            "@context": "https://w3id.org/did/v1",
            "id": "did:sov:DD3druQ4tFQHZjcwgn3KSc",
            "publicKey": [
                {
                    "id": "did:sov:DD3druQ4tFQHZjcwgn3KSc#1",
                    "type": "Ed25519VerificationKey2018",
                    "controller": "did:sov:DD3druQ4tFQHZjcwgn3KSc",
                    "publicKeyBase58": "7euiJpCar5AZMoXGspdSBhJBKzj8QZM5U3QSSSh8LAA5"
                }
            ],
            "authentication": [
                {
                    "type": "Ed25519SignatureAuthentication2018",
                    "publicKey": "did:sov:DD3druQ4tFQHZjcwgn3KSc#1"
                }
            ],
            "service": [
                {
                    "id": "did:sov:DD3druQ4tFQHZjcwgn3KSc;indy",
                    "type": "IndyAgent",
                    "priority": 0,
                    "recipientKeys": [
                        "7euiJpCar5AZMoXGspdSBhJBKzj8QZM5U3QSSSh8LAA5"
                    ],
                    "serviceEndpoint": "http://localhost:8030"
                }
            ]
        }
        """.trimJson()
        assertEquals(expDidDocument, didDocument.trimJson())

        // Verify RFC0023DidDocument serialization
        val rfC0023DidDocument = gson.fromJson(didDocument, RFC0023DidDocument::class.java)
        val was = gson.toJson(rfC0023DidDocument)
        assertEquals(expDidDocument, was)

        // Verify Did
        val didSpec = didDocument.selectJson("publicKey[0].controller") as String
        val didVerkey = didDocument.selectJson("publicKey[0].publicKeyBase58") as String
        val didSov = Did.fromSpec(didSpec, didVerkey)
        val keyId = didService.registerWithKeyStore(didSov)
        assertEquals("did:sov:DD3druQ4tFQHZjcwgn3KSc", didSov.qualified)
        assertEquals("7euiJpCar5AZMoXGspdSBhJBKzj8QZM5U3QSSSh8LAA5", didSov.verkey)

        val protected64 = attachment.selectJson("data.jws.protected") as String
        val protected = protected64.decodeBase64UrlStr() // Contains json whitespace
        log.info { "Protected: ${protected.prettyPrint()}" }

        val expJws = """
        {
            "alg": "EdDSA",
            "kid": "did:key:z6Mkm7Aku4T2Bcf2UJMyZPbH2nrB9ZzypSbSA4KNGif9FNwT",
            "jwk": {
                "kty": "OKP",
                "crv": "Ed25519",
                "x": "Ytw2nrgpEWBzEeQ2J1Jg1YbFtpSphsxvvu5QSKiu93o",
                "kid": "did:key:z6Mkm7Aku4T2Bcf2UJMyZPbH2nrB9ZzypSbSA4KNGif9FNwT"
            }
        }            
        """.trimJson()
        assertEquals(expJws, protected.trimJson())

        // The did:key referenced in the jws section is just another representation of the DidDoc publicKey
        val didKey = Did.fromSpec("did:key:z6Mkm7Aku4T2Bcf2UJMyZPbH2nrB9ZzypSbSA4KNGif9FNwT")
        assertEquals(didSov.verkey, didKey.verkey)

        // Verify the Jws signature
        val signature64 = attachment.selectJson("data.jws.signature") as String
        val signature = signature64.decodeBase64Url()
        val data = "$protected64.$didDocument64".toByteArray()
        assertTrue(cryptoService.verify(keyId, signature, data))

        // -------------------------------------------------------------------------------------------
        // Do all of the above in one API call

        val (extractedDocument, signatoryDid) = didDocumentService.extractFromAttachment(attachment)
        assertEquals(expDidDocument, gson.toJson(extractedDocument))
    }

    @Test
    fun diddoc_create_verify() {

        val seedSov = "0000000000000000000000000000000000000000000000000000000000000005".decodeHex()
        val didSov = didService.createDid(DidMethod.SOV, KeyAlgorithm.EdDSA_Ed25519, seedSov)

        val didDocument = didDocumentService.createDidDocument(didSov, "http://host.docker.internal:9030")
        val didDocumentJson = gson.toJson(didDocument)

        log.info { "Did Document: ${didDocumentJson.prettyPrint()}" }

        val attachmentJson = didDocumentService.createAttachment(didDocument, didSov)
        val attachment = gson.toJson(attachmentJson)

        log.info { "Attachment: ${attachment.prettyPrint()}" }

        val (extractedDocument, signatoryDid) = didDocumentService.extractFromAttachment(attachment)
        assertEquals(didDocumentJson, gson.toJson(extractedDocument))
    }
}
