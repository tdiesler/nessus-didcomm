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
package org.nessus.didcomm.test.service

import id.walt.common.prettyPrint
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.did.toSicpaDidDoc
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.WaltIdDid
import org.nessus.didcomm.service.WaltIdDidService
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice

class DidDocumentServiceTest: AbstractAgentTest() {
    val log = KotlinLogging.logger {}

    @Test
    fun testDidDocV2() {

        val alice = Wallet.Builder(Alice.name).build()
        try {
            val didA = alice.createDid(DidMethod.KEY)

            val didDoc: WaltIdDid = WaltIdDidService.load(didA.uri)
            log.info { "WaltIdDid: ${didDoc.encodePretty()}" }

            val didDocV2 = didService.loadDidDocument(didA.uri)
            log.info { "DidDocV2: ${didDocV2.encodeJson(true)}" }
            didDocV2.serviceEndpoint() shouldBe alice.endpointUrl

            val sicpaDidDoc = didDocV2.toSicpaDidDoc()
            log.info { "SicpaDidDoc: ${sicpaDidDoc.prettyPrint()}" }

            val didB = didService.loadDid(didA.uri)
            didB shouldBe didA

        } finally {
            removeWallet(alice)
        }
    }
}
