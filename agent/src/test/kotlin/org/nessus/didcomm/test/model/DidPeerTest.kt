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
package org.nessus.didcomm.test.model

import id.walt.common.resolveContent
import io.kotest.matchers.shouldBe
import io.kotest.matchers.shouldNotBe
import org.didcommx.peerdid.VerificationMaterialAgreement
import org.didcommx.peerdid.VerificationMaterialAuthentication
import org.didcommx.peerdid.VerificationMaterialFormatPeerDID
import org.didcommx.peerdid.VerificationMethodTypeAgreement
import org.didcommx.peerdid.VerificationMethodTypeAuthentication
import org.didcommx.peerdid.createPeerDIDNumalgo2
import org.didcommx.peerdid.isPeerDID
import org.didcommx.peerdid.resolvePeerDID
import org.nessus.didcomm.model.SicpaDidDoc
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.decodeMessage
import org.nessus.didcomm.util.trimJson

class DidPeerTest: AbstractAgentTest() {

    companion object {
        val VALID_X25519_KEY_MULTIBASE = VerificationMaterialAgreement(
            value = "z6LSbysY2xFMRpGMhb7tFTLMpeuPRaqaWM1yECx2AtzE3KCc",
            type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2020,
            format = VerificationMaterialFormatPeerDID.MULTIBASE
        )
        val VALID_ED25519_KEY_1_MULTIBASE = VerificationMaterialAuthentication(
            value = "z6MkqRYqQiSgvZQdnBytw86Qbs2ZWUkGv22od935YF4s8M7V",
            type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2020,
            format = VerificationMaterialFormatPeerDID.MULTIBASE
        )
    }

    @Test
    fun testCreateNumalgo2PositiveServiceMinimalFields() {
        val encryptionKeys = listOf(VALID_X25519_KEY_MULTIBASE)
        val signingKeys = listOf(VALID_ED25519_KEY_1_MULTIBASE)

        val service =
            """{
                "type": "DIDCommMessaging",
                "serviceEndpoint": "https://example.com/endpoint"
            }""".trimJson()

        val peerDIDAlgo2 = createPeerDIDNumalgo2(
            encryptionKeys = encryptionKeys, signingKeys = signingKeys,
            service = service
        )

        isPeerDID(peerDIDAlgo2) shouldBe true

        val diddocJson = resolvePeerDID(peerDIDAlgo2)
        log.info { diddocJson }

        val didDoc = SicpaDidDoc.fromJson(diddocJson)
        didDoc.didCommServices[0].serviceEndpoint shouldBe "https://example.com/endpoint"
    }

    @Test
    fun decodeRootsPing() {

        val msgJson = resolveContent("class:message/ping_01.json")
        val msg = msgJson.decodeMessage()

        val from = msg.from
        val to = msg.to?.firstOrNull()
        from shouldNotBe null
        to shouldNotBe null

        val fromDidDoc = didService.resolveDidDoc(from!!)
        log.info { "From DidDoc: ${fromDidDoc?.encodeJson(true)}" }

        val toDidDoc = didService.resolveDidDoc(to!!)
        log.info { "To DidDoc: ${toDidDoc?.encodeJson(true)}" }

        fromDidDoc shouldNotBe null
        toDidDoc shouldNotBe null
    }
}
