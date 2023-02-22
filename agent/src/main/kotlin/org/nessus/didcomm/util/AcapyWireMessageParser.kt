/*-
 * #%L
 * Nessus DIDComm :: Agent
 * %%
 * Copyright (C) 2022 - 2023 Nessus
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
package org.nessus.didcomm.util

import id.walt.common.prettyPrint
import mu.KotlinLogging

object AcapyWireMessageParser {
    val log = KotlinLogging.logger {}

    /**
     * Parse messages from the AcaPy debug log
     *
     * docker compose logs -f acapy01 2> /dev/null | grep Expanded
     * docker compose logs -f acapy02 2> /dev/null | grep Expanded
     */
    fun parseWireMessages(messages: List<String>) {

        messages
            .filter { it.contains("DEBUG Expanded message") }
            .map {
                val toks = it.trim().split(' ')
                val agent = toks[0]
                val tstamp = "${toks[3]} ${toks[4]}"
                val idx = it.indexOf(": {") + 2
                val msg = it.substring(idx).trimJson()
                Pair(tstamp, Pair(agent, msg))
            }.sortedBy { it.first }
            .forEach {
                val tstamp = it.first
                val agent = it.second.first
                val msg = it.second.second
                log.info { "$tstamp $agent\n${msg.prettyPrint()}" }

                val diddoc64 = msg.selectJson("did_doc~attach.data.base64")
                diddoc64?.run {
                    val diddoc = diddoc64.decodeBase64UrlStr()
                    log.info { "$tstamp $agent\n${diddoc.prettyPrint()}" }
                }
            }
    }
}
