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
package org.nessus.didcomm.test.model.dcv2

import org.nessus.didcomm.util.trimJson

class OutOfBand {

    companion object {

        const val ALICE_DID = "did:example:alice"
        const val FABER_DID = "did:example:faber"

        val FABER_OUT_OF_BAND_INVITATION = """
        {
          "type": "https://didcomm.org/out-of-band/2.0/invitation",
          "id": "1234567890",
          "from": "did:example:faber",
          "body": {
            "goal_code": "issue-vc",
            "goal": "To issue a Faber College Graduate credential",
            "accept": [
              "didcomm/v2",
              "didcomm/aip2;env=rfc587"
            ]
          },
          "attachments": [
            {
                "id": "request-0",
                "media_type": "application/json",
                "data": {
                    "json": {"protocol message": "content"}
                }
            }
          ]
        }                
        """.trimJson()

        val FABER_OUT_OF_BAND_INVITATION_WRAPPED = """
        {
          "type": "https://didcomm.org/out-of-band/2.0/invitation",
          "id": "1234567890",
          "from": "did:example:faber",
          "body": {
            "goal_code": "issue-vc",
            "goal": "To issue a Faber College Graduate credential",
            "accept": [
              "didcomm/v2",
              "didcomm/aip2;env=rfc587"
            ]
          },
          "attachments": [
            {
                "id": "0fa20500-2677-4e72-a8b3-dfff26ae2044",
                "media_type": "application/json",
                "data": {
                    "json": {
                      "invitation": {
                        "@type": "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/out-of-band/1.1/invitation",
                        "@id": "0fa20500-2677-4e72-a8b3-dfff26ae2044",
                        "label": "Aries Cloud Agent",
                        "services": [
                          {
                            "id": "#inline",
                            "type": "did-communication",
                            "recipientKeys": [
                              "did:key:z6MkqQUeLBtuYvef7BS1wvUjCJj1hskcs94tY38dKy1fzCsL"
                            ],
                            "serviceEndpoint": "http://localhost:8030"
                          }
                        ],
                        "handshake_protocols": [
                          "did:sov:BzCbsNYhMrjHiqZDTUASHg;spec/didexchange/1.0"
                        ]
                      },
                      "state": "initial",
                      "oob_id": "f2f24452-f43c-4a08-bf5c-5e6734d3f0db",
                      "invi_msg_id": "0fa20500-2677-4e72-a8b3-dfff26ae2044"
                    }
                }
            }
          ]
        }                
        """.trimJson()

        val ALICE_OUT_OF_BAND_INVITATION = """
        {
          "type": "https://didcomm.org/out-of-band/2.0/invitation",
          "id": "69212a3a-d068-4f9d-a2dd-4741bca89af3",
          "from": "did:example:alice",
          "body": {
              "goal_code": "",
              "goal": ""
          },
          "attachments": [
              {
                  "id": "request-0",
                  "media_type": "application/json",
                  "data": {
                      "base64": "qwerty"
                  }
              }
          ]
        }        
        """.trimJson()
   }
}
