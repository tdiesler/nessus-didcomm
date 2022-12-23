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
package org.nessus.didcomm.test.message

import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.util.JSONObjectUtils
import mu.KotlinLogging
import org.didcommx.didcomm.DIDComm
import org.didcommx.didcomm.common.SignAlg
import org.didcommx.didcomm.model.PackSignedParams
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.test.fixtures.JWM
import org.didcommx.didcomm.test.fixtures.JWS
import org.didcommx.didcomm.test.fixtures.isJDK15Plus
import org.didcommx.didcomm.test.mock.AliceSecretResolverMock
import org.didcommx.didcomm.test.mock.DIDDocResolverMock
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals


class SignedMessageTest {

    private val log = KotlinLogging.logger {}

    @Test
    fun testSignedPackUnpack() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        for (test in JWS.TEST_VECTORS) {

            val signAlg = test.expectedMetadata.signAlg

            // TODO: secp256k1 is not supported with JDK 15+
            if (isJDK15Plus() && signAlg == SignAlg.ES256K) {
                log.debug("Signing skip $signAlg")
                continue
            }

            log.debug("Signing with $signAlg")

            val packed = didComm.packSigned(
                PackSignedParams.builder(JWM.PLAINTEXT_MESSAGE, test.from).build()
            )

            val unpacked = didComm.unpack(
                UnpackParams.Builder(packed.packedMessage).build()
            )

            val expected = JWSObjectJSON.parse(test.expected)
            val signed = JWSObjectJSON.parse(packed.packedMessage)

            assertEquals(expected.signatures.first().header.toString(), signed.signatures.first().header.toString())

            assertEquals(
                JSONObjectUtils.toJSONString(JWM.PLAINTEXT_MESSAGE.toJSONObject()),
                JSONObjectUtils.toJSONString(unpacked.message.toJSONObject())
            )

            assertEquals(false, unpacked.metadata.encrypted)
            assertEquals(true, unpacked.metadata.authenticated)
            assertEquals(true, unpacked.metadata.nonRepudiation)
            assertEquals(false, unpacked.metadata.anonymousSender)
            assertEquals(test.expectedMetadata.signFrom, unpacked.metadata.signFrom)
            assertEquals(signAlg, unpacked.metadata.signAlg)
        }
    }
}
