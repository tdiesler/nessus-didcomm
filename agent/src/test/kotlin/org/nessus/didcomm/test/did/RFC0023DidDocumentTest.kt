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

import com.google.gson.JsonObject
import org.junit.jupiter.api.Test
import org.nessus.didcomm.protocol.RFC0023DidDocument
import org.nessus.didcomm.test.AbstractDidcommTest
import org.nessus.didcomm.util.gson
import kotlin.test.assertEquals

class RFC0023DidDocumentTest: AbstractDidcommTest() {

    @Test
    @Suppress("UNCHECKED_CAST")
    fun test_DidDocument() {

        val fixture = """
        {
            "@context": "https://w3id.org/did/v1",
            "id": "did:sov:UyXWQepD9HCxfQCh1sJRdc",
            "publicKey": [
                {
                    "id": "did:sov:UyXWQepD9HCxfQCh1sJRdc#1",
                    "type": "Ed25519VerificationKey2018",
                    "controller": "did:sov:UyXWQepD9HCxfQCh1sJRdc",
                    "publicKeyBase58": "GFLFD3Cx6LfoMbBJDWDEpJ4XTsGqS5cmMUmYiC72FZA1"
                }
            ],
            "authentication": [
                {
                    "type": "Ed25519SignatureAuthentication2018",
                    "publicKey": "did:sov:UyXWQepD9HCxfQCh1sJRdc#1"
                }
            ],
            "service": [
                {
                    "id": "did:sov:UyXWQepD9HCxfQCh1sJRdc;indy",
                    "type": "IndyAgent",
                    "priority": 0,
                    "recipientKeys": [
                        "GFLFD3Cx6LfoMbBJDWDEpJ4XTsGqS5cmMUmYiC72FZA1"
                    ],
                    "serviceEndpoint": "http://localhost:8030"
                }
            ]
        }
        """.trimIndent()

        val expObj = gson.fromJson(fixture, JsonObject::class.java)
        val exp = gson.toJson(expObj)

        val didDocument = gson.fromJson(fixture, RFC0023DidDocument::class.java)
        val was = gson.toJson(didDocument)
        assertEquals(exp, was)
    }
}
