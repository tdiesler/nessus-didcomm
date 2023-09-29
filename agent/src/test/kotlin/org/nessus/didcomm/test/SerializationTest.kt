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
package org.nessus.didcomm.test

import id.walt.signatory.revocation.RevocationResult
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.didcommx.didcomm.protocols.routing.PROFILE_DIDCOMM_V2
import org.junit.jupiter.api.Test
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.gsonPretty
import org.nessus.didcomm.util.selectJson
import org.nessus.didcomm.util.toDeeplySortedMap

class SerializationTest {
    val log = KotlinLogging.logger {}

    @Test
    fun testRevocationResult() {

        val exp = RevocationResult(true, "foo")
        val json = exp.encodeJson()
        log.info { json }

        val was = gson.fromJson(json, RevocationResult::class.java)
        log.info { was }
   }
}
