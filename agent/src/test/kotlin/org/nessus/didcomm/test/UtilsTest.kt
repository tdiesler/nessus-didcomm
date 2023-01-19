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

import org.junit.jupiter.api.Test
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.prettyGson
import org.nessus.didcomm.util.selectJson
import org.nessus.didcomm.util.toDeeplySortedMap
import kotlin.test.assertEquals

class UtilsTest: AbstractDidcommTest() {

    @Test
    fun deeplySortedMap() {

        val fixture = """
        {
          "trace": false,
          "invitation": {
            "@type": "https://didcomm.org/out-of-band/1.1/invitation",
            "@id": "f3ea944d-ad92-42d8-b6e2-d14f2d6cee10",
            "accept": [
              "didcomm/v2"
            ],
            "label": "Invitation for Alice",
            "handshake_protocols": [
              "https://didcomm.org/didexchange/1.0"
            ],
            "services": [
              {
                "id": "#inline",
                "type": "did-communication",
                "recipientKeys": [
                  "did:key:z6MkmK97sF2Ki68ETqH2fweyPSdptmBH7xJrFFphtE6eFpG9"
                ],
                "serviceEndpoint": "http://192.168.0.10:8030"
              }
            ]
          },
          "oob_id": "63a0a5fa-a207-4e92-83e6-17725c4d4490",
          "invi_msg_id": "f3ea944d-ad92-42d8-b6e2-d14f2d6cee10",
          "invitation_url": "http://192.168.0.10:8030?oob=eyJAdHlwZ...MzAifV19",
          "state": "initial"
        }
        """.trimIndent()

        assertEquals("f3ea944d-ad92-42d8-b6e2-d14f2d6cee10", fixture.selectJson("invitation.@id"))
        assertEquals("didcomm/v2", fixture.selectJson("invitation.accept[0]"))

        val exp = """
        {
          "invi_msg_id": "f3ea944d-ad92-42d8-b6e2-d14f2d6cee10",
          "invitation": {
            "@id": "f3ea944d-ad92-42d8-b6e2-d14f2d6cee10",
            "@type": "https://didcomm.org/out-of-band/1.1/invitation",
            "accept": [
              "didcomm/v2"
            ],
            "handshake_protocols": [
              "https://didcomm.org/didexchange/1.0"
            ],
            "label": "Invitation for Alice",
            "services": [
              {
                "id": "#inline",
                "recipientKeys": [
                  "did:key:z6MkmK97sF2Ki68ETqH2fweyPSdptmBH7xJrFFphtE6eFpG9"
                ],
                "serviceEndpoint": "http://192.168.0.10:8030",
                "type": "did-communication"
              }
            ]
          },
          "invitation_url": "http://192.168.0.10:8030?oob\u003deyJAdHlwZ...MzAifV19",
          "oob_id": "63a0a5fa-a207-4e92-83e6-17725c4d4490",
          "state": "initial",
          "trace": false
        }
        """.trimIndent()

        @Suppress("UNCHECKED_CAST")
        val inputMap = gson.fromJson(fixture, Map::class.java) as Map<String, Any?>
        val sortedMap = inputMap.toDeeplySortedMap()

        val was = prettyGson.toJson(sortedMap)
        log.info { was }

        assertEquals(exp, was)
    }

    @Test
    fun encode_decode_json() {

        // Naive decoding of int values may produce double
        val map = mapOf("foo" to 0)

        val exp = gson.toJson(map)
        val was = map.encodeJson()

        log.info { was }
        assertEquals(exp, was)

        val decoded = was.decodeJson()
        assertEquals(map, decoded)
    }
}
