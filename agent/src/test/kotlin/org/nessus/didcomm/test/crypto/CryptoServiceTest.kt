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
package org.nessus.didcomm.test.crypto

import id.walt.common.prettyPrint
import id.walt.crypto.KeyAlgorithm
import id.walt.services.crypto.CryptoService
import org.junit.jupiter.api.Test
import org.nessus.didcomm.crypto.NessusCryptoService
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.test.AbstractDidcommTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.util.decodeBase58
import org.nessus.didcomm.util.decodeBase64Str
import org.nessus.didcomm.util.decodeBase64Url
import org.nessus.didcomm.util.decodeHex
import org.nessus.didcomm.util.encodeBase58
import org.nessus.didcomm.util.selectJson
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class CryptoServiceTest: AbstractDidcommTest() {

    @Test
    fun signVerifySeedMessage() {

        val cryptoService = CryptoService.getService().implementation as NessusCryptoService
        val keyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Alice.seedHex.decodeHex())

        val data = "Hello".toByteArray()
        val signature = cryptoService.sign(keyId, data)
        assertTrue(cryptoService.verify(keyId, signature, data))
    }

    @Test
    fun verifyAttachedDoc() {

        val attachedDidDoc = """
        {
            "@id": "0d154716-9dc2-4cfb-b9ec-835dfe6695a0",
            "data": {
              "base64": "eyJAY29udGV4dCI6ICJodHRwczovL3czaWQub3JnL2RpZC92MSIsICJpZCI6ICJkaWQ6c292OkY5R2szQkRYeGtRalJoVDVONVpCVWEiLCAicHVibGljS2V5IjogW3siaWQiOiAiZGlkOnNvdjpGOUdrM0JEWHhrUWpSaFQ1TjVaQlVhIzEiLCAidHlwZSI6ICJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCIsICJjb250cm9sbGVyIjogImRpZDpzb3Y6RjlHazNCRFh4a1FqUmhUNU41WkJVYSIsICJwdWJsaWNLZXlCYXNlNTgiOiAiOGk1UHprSHZZYVpXSm9wYmNCODZrUGpXeHNENTEyQjk1MTJ5a3NmRmM0NlYifV0sICJhdXRoZW50aWNhdGlvbiI6IFt7InR5cGUiOiAiRWQyNTUxOVNpZ25hdHVyZUF1dGhlbnRpY2F0aW9uMjAxOCIsICJwdWJsaWNLZXkiOiAiZGlkOnNvdjpGOUdrM0JEWHhrUWpSaFQ1TjVaQlVhIzEifV0sICJzZXJ2aWNlIjogW3siaWQiOiAiZGlkOnNvdjpGOUdrM0JEWHhrUWpSaFQ1TjVaQlVhO2luZHkiLCAidHlwZSI6ICJJbmR5QWdlbnQiLCAicHJpb3JpdHkiOiAwLCAicmVjaXBpZW50S2V5cyI6IFsiOGk1UHprSHZZYVpXSm9wYmNCODZrUGpXeHNENTEyQjk1MTJ5a3NmRmM0NlYiXSwgInNlcnZpY2VFbmRwb2ludCI6ICJodHRwOi8vbG9jYWxob3N0OjgwMzAifV19",
              "jws": {
                "header": {
                  "kid": "did:key:z6MknALSazYMt83yRJfJHk5wbVHWnSUvQuRVm1wub9dGXGss"
                },
                "protected": "eyJhbGciOiAiRWREU0EiLCAia2lkIjogImRpZDprZXk6ejZNa25BTFNhellNdDgzeVJKZkpIazV3YlZIV25TVXZRdVJWbTF3dWI5ZEdYR3NzIiwgImp3ayI6IHsia3R5IjogIk9LUCIsICJjcnYiOiAiRWQyNTUxOSIsICJ4IjogImNvZVh2NmYxamhERTladDdaNlo3QjBROWYxZ3VBMkN3ejd2SU9JZTdOc0kiLCAia2lkIjogImRpZDprZXk6ejZNa25BTFNhellNdDgzeVJKZkpIazV3YlZIV25TVXZRdVJWbTF3dWI5ZEdYR3NzIn19",
                "signature": "or77mwWXZ3ohLyAzg5ChNcB6Oqx5BHQoULLmU6b5CxzK1T695Vf30kpl_cHB_ooBamXDEbuxtKWJ4hymVxvHAA"
              }
            },
            "mime-type": "application/json"
        }
        """.trimIndent()

        val dataBase64 = attachedDidDoc.selectJson("data.base64") as String
        val didDocument = dataBase64.decodeBase64Str()
        log.info { "Did Document: ${didDocument.prettyPrint()}" }

        val dataJwsProtected64 = attachedDidDoc.selectJson("data.jws.protected") as String
        val dataJwsSignature = attachedDidDoc.selectJson("data.jws.signature") as String
        val protected = dataJwsProtected64.decodeBase64Str()
        val signature = dataJwsSignature.decodeBase64Url()
        log.info { "Protected: ${protected.prettyPrint()}" }

        // Extract the Did + Verkey
        val didSovExt = didDocument.selectJson("publicKey[0].id") as String
        val verkey58 = didDocument.selectJson("publicKey[0].publicKeyBase58") as String
        val didSov = Did.fromSpec(didSovExt.split("#")[0], verkey58)
        val verkey = verkey58.decodeBase58()

        // did:sov uses the first 16 bytes from the (32 byte) verkey
        val id = verkey.dropLast(16).toByteArray().encodeBase58()
        assertEquals(didSov.qualified, "did:sov:$id")
        assertEquals(didSov.verkey, verkey58)

        // Register the Did with the KeyStore for later use by the CryptoService
        val cryptoService = CryptoService.getService().implementation as NessusCryptoService
        val keyId = DidService.getService().registerVerkey(didSov)

        // Verify the integrity of the Did Document
        val data = "$dataJwsProtected64.$dataBase64".toByteArray()
        assertTrue(cryptoService.verify(keyId, signature, data))
    }
}
