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
import mu.KotlinLogging
import org.didcommx.didcomm.message.Message
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.decodeJson
import java.io.File

class MessageTest: AbstractAgentTest() {
    val log = KotlinLogging.logger {}

    @Test
    fun decodeEncode() {

        val messagesDir = "src/main/resources/dashboard/messages"
        File(messagesDir).walk().sorted()
            .filter { it.isFile }
            .forEach { f ->
                val json = resolveContent(f.canonicalPath)
                val m = runCatching { Message.parse(json.decodeJson()) }
                    .onFailure { throw IllegalStateException("Cannot parse: $f", it) }
                log.info { m }
            }
    }
}
