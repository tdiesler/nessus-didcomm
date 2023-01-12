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

import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.encodeBase58
import id.walt.services.keystore.KeyType
import org.junit.jupiter.api.Test
import org.nessus.didcomm.crypto.convertEd25519toRaw
import org.nessus.didcomm.service.PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE
import org.nessus.didcomm.test.AbstractDidcommTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.Faber
import kotlin.test.assertEquals

class RFC0019EnvelopeTest: AbstractDidcommTest() {

    @Test
    fun pack_unpack_envelope() {

        val faberKeyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Faber.seed.toByteArray())
        val faberKeys = keyStore.load(faberKeyId.id, KeyType.PRIVATE).keyPair!!
        val faberVerkey = faberKeys.public.convertEd25519toRaw().encodeBase58()
        keyStore.addAlias(faberKeyId, faberVerkey)

        val aliceKeyId = cryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519, Alice.seed.toByteArray())
        val aliceKeys = keyStore.load(aliceKeyId.id, KeyType.PRIVATE).keyPair!!
        val aliceVerkey = aliceKeys.public.convertEd25519toRaw().encodeBase58()
        keyStore.addAlias(aliceKeyId, aliceVerkey)

        val rfc0019 = protocolService.getProtocol(PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE)
        val envelope = rfc0019.packRFC0019Envelope(faberKeys, aliceKeys.public, "Scheena Dog")
        val message = rfc0019.unpackRFC0019Envelope(envelope)
        assertEquals("Scheena Dog", message)
    }

}

