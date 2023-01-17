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
            "@type": "https://didcomm.org/didexchange/1.0/request",
            "@id": "130d9ccd-652d-4e57-80c4-22e1f28c9ad2",
            "~thread": {
                "thid": "130d9ccd-652d-4e57-80c4-22e1f28c9ad2",
                "pthid": "43ccec84-c5a4-4378-9cd0-ae6607ea67fb"
            },
            "label": "Aries Cloud Agent",
            "did": "DngzknmPCjQhnZ6SinQZtr",
            "did_doc~attach": {
                "@id": "f09caf59-d971-4ada-8571-79ffed6ea745",
                "mime-type": "application/json",
                "data": {
                    "base64": "eyJAY29udGV...gwMzAifV19",
                    "jws": {
                        "header": {
                            "kid": "did:key:z6MkmRWKF37kpn2XWbjR2R2CkejQtPaZBarffuowV3y8U6g7"
                        },
                        "protected": "eyJhbGciOiA...hVNmc3In19",
                        "signature": "VFqhX3jGiZC-Ypu0Yj7-pdqMC5q_p8fvtpoDhtoJ4XNd-JOVPZe6Gz4pM_IxB_FkX_obaKIQ7rur-IBQu4KlDA"
                    }
                }
            }
        }
        """.trimIndent()

        val pthid = fixture.selectJson("~thread.pthid")
        assertEquals("43ccec84-c5a4-4378-9cd0-ae6607ea67fb", pthid)

        val exp = """
        {
          "@id": "130d9ccd-652d-4e57-80c4-22e1f28c9ad2",
          "@type": "https://didcomm.org/didexchange/1.0/request",
          "~thread": {
            "pthid": "43ccec84-c5a4-4378-9cd0-ae6607ea67fb",
            "thid": "130d9ccd-652d-4e57-80c4-22e1f28c9ad2"
          },
          "did": "DngzknmPCjQhnZ6SinQZtr",
          "did_doc~attach": {
            "@id": "f09caf59-d971-4ada-8571-79ffed6ea745",
            "data": {
              "base64": "eyJAY29udGV...gwMzAifV19",
              "jws": {
                "header": {
                  "kid": "did:key:z6MkmRWKF37kpn2XWbjR2R2CkejQtPaZBarffuowV3y8U6g7"
                },
                "protected": "eyJhbGciOiA...hVNmc3In19",
                "signature": "VFqhX3jGiZC-Ypu0Yj7-pdqMC5q_p8fvtpoDhtoJ4XNd-JOVPZe6Gz4pM_IxB_FkX_obaKIQ7rur-IBQu4KlDA"
              }
            },
            "mime-type": "application/json"
          },
          "label": "Aries Cloud Agent"
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
