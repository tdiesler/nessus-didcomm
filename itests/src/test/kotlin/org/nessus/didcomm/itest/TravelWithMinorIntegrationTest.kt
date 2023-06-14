/*-
 * #%L
 * Nessus DIDComm :: ITests
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
package org.nessus.didcomm.itest

import id.walt.common.resolveContent
import io.kotest.core.annotation.EnabledIf
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.nessus.didcomm.util.NessusPlaygroundReachable
import java.util.concurrent.atomic.AtomicInteger

/**
 * Use Case: International Travel with Minor
 * https://www.w3.org/TR/vc-use-cases/#international-travel-with-minor-and-upgrade
 */
@EnabledIf(NessusPlaygroundReachable::class)
class TravelWithMinorIntegrationTest<T: AutoCloseable> : AbstractIntegrationTest() {
    private val log = KotlinLogging.logger { }

    @Test
    fun travelWithMinor_DidKey() {

        val content = resolveContent("../cli/etc/script/travel-with-minor-client.txt")
        val lines = content.lines()
            .filter { it.isNotEmpty() }
            .filter { !it.startsWith("#") }
            .toMutableList()

        val idxHolder = AtomicInteger(0)
        while (lines.isNotEmpty()) {
            val command = cliService.nextCommand(lines)
            if (command != null) {
                val idx = idxHolder.incrementAndGet()
                log.info { "\n[${idx}] $command" }
                cliService.execute(command).isSuccess shouldBe true
            }
        }
    }
}
