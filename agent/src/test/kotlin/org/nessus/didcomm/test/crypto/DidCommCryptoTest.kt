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
import io.kotest.matchers.shouldBe
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.service.toOctetKeyPair
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.decodeHex
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.trimJson

/**
 * did:key test vectors
 * https://w3c-ccg.github.io/did-method-key/#test-vectors
 * https://github.com/w3c-ccg/did-method-key/tree/main/test-vectors
 */
class DidCommCryptoTest: AbstractAgentTest() {

    @Test
    fun extract_key_from_Ed25519VerificationKey2018() {

        // ed25519-x25519.json
        val seed = "0000000000000000000000000000000000000000000000000000000000000005".decodeHex()
        val keyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, seed)
        val did = didService.createDid(DidMethod.KEY, keyAlias = keyId.id)
        did.uri shouldBe "did:key:z6MkwYMhwTvsq376YBAcJHy3vyRWzBgn5vKfVqqDCgm7XVKU"

        val octetKeyPair = didService.loadDid(did.uri).toOctetKeyPair()

        val jwk = octetKeyPair.toJSONObject().encodeJson()
        log.info { jwk.prettyPrint() }

        val exp = """
        {
            "alg":"EdDSA",
            "crv":"Ed25519",
            "d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU",
            "kid":"$keyId",
            "kty":"OKP",
            "use":"sig",
            "x":"_eT7oDCtAC98L31MMx9J0T-w7HR-zuvsY08f9MvKne8"
        }            
        """.trimJson()
        jwk.decodeJson() shouldBe exp.decodeJson()
    }

    @Test
    fun extract_key_from_Ed25519VerificationKey2018_secret() {

        // ed25519-x25519.json
        val seed = "0000000000000000000000000000000000000000000000000000000000000005".decodeHex()
        val keyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, seed)
        val did = didService.createDid(DidMethod.KEY, keyAlias = keyId.id)
        did.uri shouldBe "did:key:z6MkwYMhwTvsq376YBAcJHy3vyRWzBgn5vKfVqqDCgm7XVKU"

        val octetKeyPair = didService.loadDid(did.uri).toOctetKeyPair()

        val jwk = octetKeyPair.toJSONObject().encodeJson()
        log.info { jwk.prettyPrint() }

        val exp = """
        {
            "alg":"EdDSA",
            "crv":"Ed25519",
            "d":"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAU",
            "kid":"$keyId",
            "kty":"OKP",
            "use":"sig",
            "x":"_eT7oDCtAC98L31MMx9J0T-w7HR-zuvsY08f9MvKne8"
        }            
        """.trimJson()
        jwk.decodeJson() shouldBe exp.decodeJson()
    }
}
