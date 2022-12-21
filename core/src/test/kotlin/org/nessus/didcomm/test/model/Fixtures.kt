package org.nessus.didcomm.test.model

import org.nessus.didcomm.model.MessageReader

class OutOfBand {

    companion object {

        const val ALICE_DID = "did:example:alice"
        const val FABER_DID = "did:example:faber"

        val FABER_OUT_OF_BAND_INVITATION = MessageReader.fromJson("""
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
        """.trimIndent())

        val FABER_OUT_OF_BAND_INVITATION_WRAPPED = MessageReader.fromJson("""
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
        """.trimIndent())

        val ALICE_OUT_OF_BAND_INVITATION = MessageReader.fromJson("""
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
        """.trimIndent())
   }
}
