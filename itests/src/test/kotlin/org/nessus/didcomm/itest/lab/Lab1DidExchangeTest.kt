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
package org.nessus.didcomm.itest.lab

import id.walt.common.prettyPrint
import org.hyperledger.acy_py.generated.model.InvitationRecord
import org.hyperledger.aries.api.did_exchange.DidExchangeAcceptInvitationFilter
import org.hyperledger.aries.api.out_of_band.CreateInvitationFilter
import org.hyperledger.aries.api.out_of_band.InvitationCreateRequest
import org.hyperledger.aries.api.out_of_band.InvitationMessage
import org.hyperledger.aries.api.out_of_band.ReceiveInvitationFilter
import org.junit.jupiter.api.Test
import org.nessus.didcomm.agent.AriesAgent.Companion.awaitConnectionRecord
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.itest.ACAPY_OPTIONS_02
import org.nessus.didcomm.itest.AbstractIntegrationTest
import org.nessus.didcomm.itest.Alice
import org.nessus.didcomm.itest.Faber
import org.nessus.didcomm.util.WireMessageParser.parseWireMessages
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.prettyGson
import org.nessus.didcomm.util.sortedJson
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.StorageType
import org.nessus.didcomm.wallet.Wallet
import kotlin.test.fail

/**
 * DIDComm - Out Of Band Messages
 * https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages
 *
 * Aries RFC 0434: Out-of-Band Protocol 1.1
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0434-outofband
 *
 * Aries RFC 0023: DID Exchange Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
 *
 * Flow Overview
 * 1. The responder gives provisional information to the requester using an explicit invitation message from the
 *    out-of-band protocol or an implicit invitation in a DID the responder publishes.
 * 2. The requester uses the provisional information to send a DID and DID Doc to the responder in a request message.
 * 3. The responder uses sent DID Doc information to send a DID and DID Doc to the requester in a response message.
 * 4. The requester sends the responder a complete message that confirms the response message was received.
 */
class Lab1DidExchangeTest : AbstractIntegrationTest() {

    @Test
    fun test_FaberAcapy_invites_AliceAcapy() {

        val faber = getWalletByAlias(Faber.name) ?: fail("No Faber")

        val alice = Wallet.Builder(Alice.name)
            .options(ACAPY_OPTIONS_02)
            .agentType(AgentType.ACAPY)
            .storageType(StorageType.IN_MEMORY)
            .build()

        val faberClient = faber.walletClient() as AriesClient
        val aliceClient = alice.walletClient() as AriesClient

        faber.openWebSocket {
            log.info { "WebSocket ${faber.name}: ${it.topic}" }
            log.info { it.payload.sortedJson().prettyPrint() }
        }

        alice.openWebSocket {
            log.info { "WebSocket ${alice.name}: ${it.topic}" }
            log.info { it.payload.sortedJson().prettyPrint() }
        }

        try {

            val faberAutoAccept = true
            val aliceAutoAccept = false

            /**
             * Inviter (Faber) creates an Out-of-Band Invitation
             */

            val createInvRequest = InvitationCreateRequest.builder()
                .accept(listOf("didcomm/v2"))
                .alias("${faber.name}/${alice.name}")
                .myLabel("Invitation for ${alice.name}")
                .handshakeProtocols(listOf("https://didcomm.org/didexchange/1.0"))
                .protocolVersion("1.1")
                .usePublicDid(false)
                .build()
            val createInvFilter = CreateInvitationFilter.builder()
                .autoAccept(faberAutoAccept)
                .build()
            val faberInvRecord: InvitationRecord = faberClient.outOfBandCreateInvitation(createInvRequest, createInvFilter).get()
            val invitation = faberInvRecord.invitation
            val invitationId = invitation.atId

            // Expect inviter connection in state 'invitation'
            var faberConnection = awaitConnectionRecord(faber) {
                it.invitationMsgId == invitationId && it.stateIsInvitation()
            }
            checkNotNull(faberConnection) {"${faber.name} has no connection record in state 'invitation'"}
            log.info {"${faber.name} connection: ${faberConnection?.state}"}
            log.info("${faber.name}: {}", prettyGson.toJson(faberConnection))

            /**
             * Invitee (Alice) receives the Invitation
             */

            val invitationMessageBuilder = InvitationMessage.builder<InvitationMessage.InvitationMessageService>()
                .services(invitation.services.map {
                    val srvJson: String = gson.toJson(it)
                    gson.fromJson(srvJson, InvitationMessage.InvitationMessageService::class.java)
                })
            val invitationMessage = invitationMessageBuilder.atId(invitation.atId)
                .atType(invitation.atType)
                .goalCode("issue-vc")
                .goalCode("Issue a Faber College Graduate credential")
                .accept(invitation.accept)
                .build()
            val receiveInvFilter = ReceiveInvitationFilter.builder()
                .useExistingConnection(false)
                .autoAccept(aliceAutoAccept)
                .build()
            aliceClient.outOfBandReceiveInvitation(invitationMessage, receiveInvFilter).get()

            // Expect invitee connection in state 'invitation'
            var aliceConnection = awaitConnectionRecord(alice) {
                it.invitationMsgId == invitationId && it.stateIsInvitation()
            }
            checkNotNull(aliceConnection) {"${alice.name} has no connection record in state 'invitation'"}
            log.info {"${alice.name} connection: ${aliceConnection?.state}"}
            log.info("${alice.name}: {}", prettyGson.toJson(aliceConnection))

            /**
             * Invitee (Alice) manually accepts the Invitation
             */

            if (!aliceAutoAccept) {
                val acceptInvitationFilter = DidExchangeAcceptInvitationFilter()
                acceptInvitationFilter.myEndpoint = alice.endpointUrl
                acceptInvitationFilter.myLabel = "Accept Faber/Alice"
                val inviteeConnectionId = aliceConnection.connectionId
                aliceClient.didExchangeAcceptInvitation(inviteeConnectionId, acceptInvitationFilter).get()
            }

            /**
             * Inviter (Faber) manually accepts the Invitation
             *
             * Note, this will currently not work because of ...
             * No explicit invitation found for pairwise connection
             *
             * It seems that Faber needs to receive an oob invitation too.
             * We won't worry about this for now (i.e. Faber needs to auto_accept)
             */

            if (!faberAutoAccept) {
                val acceptInvitationFilter = DidExchangeAcceptInvitationFilter()
                acceptInvitationFilter.myEndpoint = faber.endpointUrl
                acceptInvitationFilter.myLabel = "Accept Faber/Alice"
                val inviterConnectionId = faberConnection.connectionId
                faberClient.didExchangeAcceptInvitation(inviterConnectionId, acceptInvitationFilter).get()
            }

            /**
             * Invitee (Alice) awaits her active Connection
             */

            aliceConnection = awaitConnectionRecord(alice) {
                it.invitationMsgId == invitationId && it.stateIsActive()
            }
            checkNotNull(aliceConnection) {"${alice.name} has no connection record in state 'active'"}
            log.info {"${alice.name} connection: ${aliceConnection.state}"}
            log.info("${alice.name}: {}", prettyGson.toJson(aliceConnection))

            /**
             * Inviter (Faber) awaits it's active Connection
             */

            faberConnection = awaitConnectionRecord(faber) {
                it.invitationMsgId == invitationId && it.stateIsActive()
            }
            checkNotNull(faberConnection) {"${faber.name} has no connection record in state 'active'"}
            log.info {"${faber.name} connection: ${faberConnection.state}"}
            log.info("${faber.name}: {}", prettyGson.toJson(faberConnection))

        } finally {
            faber.removeConnections()
            removeWallet(Alice.name)
        }
    }

    @Test
    fun test_FaberAcapy_invites_AliceAcapy_WireMessages() {

        parseWireMessages("""
            acapy01  | 2023-01-20 13:34:15,254 aries_cloudagent.transport.pack_format DEBUG Expanded message: {'@type': 'https://didcomm.org/didexchange/1.0/request', '@id': 'a3b9187d-b9fe-4ae4-8216-7d3de4c5fb5f', '~thread': {'thid': 'a3b9187d-b9fe-4ae4-8216-7d3de4c5fb5f', 'pthid': '31994d69-63b9-4fcb-a3c4-b25883b13587'}, 'label': 'Accept Faber/Alice', 'did': 'TNxfmr8bhmwiwxMdF9hRAb', 'did_doc~attach': {'@id': 'bf7af0df-19f2-40c7-ac85-c117cc0f20d3', 'mime-type': 'application/json', 'data': {'base64': 'eyJAY29udGV4dCI6ICJodHRwczovL3czaWQub3JnL2RpZC92MSIsICJpZCI6ICJkaWQ6c292OlROeGZtcjhiaG13aXd4TWRGOWhSQWIiLCAicHVibGljS2V5IjogW3siaWQiOiAiZGlkOnNvdjpUTnhmbXI4Ymhtd2l3eE1kRjloUkFiIzEiLCAidHlwZSI6ICJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCIsICJjb250cm9sbGVyIjogImRpZDpzb3Y6VE54Zm1yOGJobXdpd3hNZEY5aFJBYiIsICJwdWJsaWNLZXlCYXNlNTgiOiAiRk50M2R6NVpWRTJZRG1wUG5QcDFGWlV5b3VTaTRaVmY1YzFuMVh3THpaTHIifV0sICJhdXRoZW50aWNhdGlvbiI6IFt7InR5cGUiOiAiRWQyNTUxOVNpZ25hdHVyZUF1dGhlbnRpY2F0aW9uMjAxOCIsICJwdWJsaWNLZXkiOiAiZGlkOnNvdjpUTnhmbXI4Ymhtd2l3eE1kRjloUkFiIzEifV0sICJzZXJ2aWNlIjogW3siaWQiOiAiZGlkOnNvdjpUTnhmbXI4Ymhtd2l3eE1kRjloUkFiO2luZHkiLCAidHlwZSI6ICJJbmR5QWdlbnQiLCAicHJpb3JpdHkiOiAwLCAicmVjaXBpZW50S2V5cyI6IFsiRk50M2R6NVpWRTJZRG1wUG5QcDFGWlV5b3VTaTRaVmY1YzFuMVh3THpaTHIiXSwgInNlcnZpY2VFbmRwb2ludCI6ICJodHRwOi8vMTkyLjE2OC4wLjEwOjgwNDAifV19', 'jws': {'header': {'kid': 'did:key:z6Mktq96EEKzpmX1LGf6Txmr6f2ydUiZUSk1mcvhqouMun8E'}, 'protected': 'eyJhbGciOiAiRWREU0EiLCAia2lkIjogImRpZDprZXk6ejZNa3RxOTZFRUt6cG1YMUxHZjZUeG1yNmYyeWRVaVpVU2sxbWN2aHFvdU11bjhFIiwgImp3ayI6IHsia3R5IjogIk9LUCIsICJjcnYiOiAiRWQyNTUxOSIsICJ4IjogIjFaNklBTzRBMVNQQk9TM2FIYUlsRENQSnRkRjR2WjlhSHFpNUdLTk11RmMiLCAia2lkIjogImRpZDprZXk6ejZNa3RxOTZFRUt6cG1YMUxHZjZUeG1yNmYyeWRVaVpVU2sxbWN2aHFvdU11bjhFIn19', 'signature': 'VFpj80rQ2C_YY_kYC3okdbgO6lxwItdVNIHnea9-KXNW-Cc1SG0YHbNLfvoymckevy88E0FkCf2aMChDaWw6CA'}}}}
            acapy01  | 2023-01-20 13:34:15,744 aries_cloudagent.transport.pack_format DEBUG Expanded message: {'@type': 'https://didcomm.org/didexchange/1.0/complete', '@id': '129c4f18-dac0-4d77-bf9a-15d7af2177d3', '~thread': {'thid': 'a3b9187d-b9fe-4ae4-8216-7d3de4c5fb5f', 'pthid': '31994d69-63b9-4fcb-a3c4-b25883b13587'}}
            acapy01  | 2023-01-20 13:34:15,760 aries_cloudagent.transport.pack_format DEBUG Expanded message: {'@type': 'https://didcomm.org/trust_ping/1.0/ping', '@id': '5cf45e53-4a5c-4827-801d-287cfb1121f0', 'response_requested': True}
                
            acapy02  | 2023-01-20 13:34:15,645 aries_cloudagent.transport.pack_format DEBUG Expanded message: {'@type': 'https://didcomm.org/didexchange/1.0/response', '@id': 'a195c391-6f9e-466b-a05d-3f64f36b1f27', '~thread': {'thid': 'a3b9187d-b9fe-4ae4-8216-7d3de4c5fb5f', 'pthid': '31994d69-63b9-4fcb-a3c4-b25883b13587'}, 'did_doc~attach': {'@id': 'b0917b43-1b03-468e-8cca-c16210a4a974', 'mime-type': 'application/json', 'data': {'base64': 'eyJAY29udGV4dCI6ICJodHRwczovL3czaWQub3JnL2RpZC92MSIsICJpZCI6ICJkaWQ6c292OjR5VU1CZ05HTGNDR0xBaXBxOXpab3giLCAicHVibGljS2V5IjogW3siaWQiOiAiZGlkOnNvdjo0eVVNQmdOR0xjQ0dMQWlwcTl6Wm94IzEiLCAidHlwZSI6ICJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCIsICJjb250cm9sbGVyIjogImRpZDpzb3Y6NHlVTUJnTkdMY0NHTEFpcHE5elpveCIsICJwdWJsaWNLZXlCYXNlNTgiOiAiM0FjZkR1ZnZCQ0twNlRTV1p6UkhkUlJZSDRTWUtSa2Zia01iczdRdTRxemMifV0sICJhdXRoZW50aWNhdGlvbiI6IFt7InR5cGUiOiAiRWQyNTUxOVNpZ25hdHVyZUF1dGhlbnRpY2F0aW9uMjAxOCIsICJwdWJsaWNLZXkiOiAiZGlkOnNvdjo0eVVNQmdOR0xjQ0dMQWlwcTl6Wm94IzEifV0sICJzZXJ2aWNlIjogW3siaWQiOiAiZGlkOnNvdjo0eVVNQmdOR0xjQ0dMQWlwcTl6Wm94O2luZHkiLCAidHlwZSI6ICJJbmR5QWdlbnQiLCAicHJpb3JpdHkiOiAwLCAicmVjaXBpZW50S2V5cyI6IFsiM0FjZkR1ZnZCQ0twNlRTV1p6UkhkUlJZSDRTWUtSa2Zia01iczdRdTRxemMiXSwgInNlcnZpY2VFbmRwb2ludCI6ICJodHRwOi8vMTkyLjE2OC4wLjEwOjgwMzAifV19', 'jws': {'header': {'kid': 'did:key:z6MkfBLA5kbwFsmt96rLrwqgod3aBjGKEQXKzFajWSnpk6ML'}, 'protected': 'eyJhbGciOiAiRWREU0EiLCAia2lkIjogImRpZDprZXk6ejZNa2ZCTEE1a2J3RnNtdDk2ckxyd3Fnb2QzYUJqR0tFUVhLekZhaldTbnBrNk1MIiwgImp3ayI6IHsia3R5IjogIk9LUCIsICJjcnYiOiAiRWQyNTUxOSIsICJ4IjogIkNzY0xHTDcwYjd4WkdWbVVURW9wMXhLQm1tOVRia20tc1F3ajE1ZlNydGMiLCAia2lkIjogImRpZDprZXk6ejZNa2ZCTEE1a2J3RnNtdDk2ckxyd3Fnb2QzYUJqR0tFUVhLekZhaldTbnBrNk1MIn19', 'signature': 'iJYjrt_NK5A4r1AuHOy9BkRyjO0t3PT0p2-q-t3eQwNlnQM8cA413TGvuIwAeiW_7Qlnj0fW-StEhcyJ9QROBA'}}}, 'did': '4yUMBgNGLcCGLAipq9zZox'}
            acapy02  | 2023-01-20 13:34:15,955 aries_cloudagent.transport.pack_format DEBUG Expanded message: {'@type': 'https://didcomm.org/trust_ping/1.0/ping_response', '@id': '5e49588e-fc78-4ee8-a3fb-d8dc1dcda4bf', '~thread': {'thid': '5cf45e53-4a5c-4827-801d-287cfb1121f0'}}
            """.lines())

        /*x

        // Faber issues an Out-of-Band Invitation ======================================================================

        Command: {
          "accept": [
            "didcomm/v2"
          ],
          "alias": "Faber/Alice",
          "attachments": [],
          "handshake_protocols": [
            "https://didcomm.org/didexchange/1.0"
          ],
          "my_label": "Invitation for Alice",
          "protocol_version": "1.1",
          "use_public_did": false
        }

        {
          "invi_msg_id": "31994d69-63b9-4fcb-a3c4-b25883b13587",
          "invitation": {
            "@id": "31994d69-63b9-4fcb-a3c4-b25883b13587",
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
                  "did:key:z6MkgCaVGyQgSi2HrCf4gMP1zujhCaN5C2vFZrNNuiihsZSf"
                ],
                "serviceEndpoint": "http://192.168.0.10:8030",
                "type": "did-communication"
              }
            ]
          },
          "invitation_url": "http://192.168.0.10:8030?oob\u003deyJAdHl...jgwMzAifV19",
          "oob_id": "7ac16b91-d1df-413a-a913-9e319a92c401",
          "state": "initial",
          "trace": false
        }

        // Faber receives a DidEx Request ==============================================================================
        //
        2023-01-20 13:34:15,254 acapy01
        {
            "@type": "https://didcomm.org/didexchange/1.0/request",
            "@id": "a3b9187d-b9fe-4ae4-8216-7d3de4c5fb5f",
            "~thread": {
                "thid": "a3b9187d-b9fe-4ae4-8216-7d3de4c5fb5f",
                "pthid": "31994d69-63b9-4fcb-a3c4-b25883b13587"
            },
            "label": "Accept Faber/Alice",
            "did": "TNxfmr8bhmwiwxMdF9hRAb",
            "did_doc~attach": {
                "@id": "bf7af0df-19f2-40c7-ac85-c117cc0f20d3",
                "mime-type": "application/json",
                "data": {
                    "base64": "eyJAY29...gwNDAifV19",
                    "jws": {
                        "header": {
                            "kid": "did:key:z6Mktq96EEKzpmX1LGf6Txmr6f2ydUiZUSk1mcvhqouMun8E"
                        },
                        "protected": "eyJhbGciO...bjhFIn19",
                        "signature": "VFpj80rQ2C_...DaWw6CA"
                    }
                }
            }
        }

        // Attached is Alice"s Did Document ============================================================================
        //
        2023-01-20 13:34:15,254 acapy01 {
            "@context": "https://w3id.org/did/v1",
            "id": "did:sov:TNxfmr8bhmwiwxMdF9hRAb",
            "publicKey": [
                {
                    "id": "did:sov:TNxfmr8bhmwiwxMdF9hRAb#1",
                    "type": "Ed25519VerificationKey2018",
                    "controller": "did:sov:TNxfmr8bhmwiwxMdF9hRAb",
                    "publicKeyBase58": "FNt3dz5ZVE2YDmpPnPp1FZUyouSi4ZVf5c1n1XwLzZLr"
                }
            ],
            "authentication": [
                {
                    "type": "Ed25519SignatureAuthentication2018",
                    "publicKey": "did:sov:TNxfmr8bhmwiwxMdF9hRAb#1"
                }
            ],
            "service": [
                {
                    "id": "did:sov:TNxfmr8bhmwiwxMdF9hRAb;indy",
                    "type": "IndyAgent",
                    "priority": 0,
                    "recipientKeys": [
                        "FNt3dz5ZVE2YDmpPnPp1FZUyouSi4ZVf5c1n1XwLzZLr"
                    ],
                    "serviceEndpoint": "http://192.168.0.10:8040"
                }
            ]
        }

        // Alice receives a DidEx Response =============================================================================
        //
        2023-01-20 13:34:15,645 acapy02
        {
            "@type": "https://didcomm.org/didexchange/1.0/response",
            "@id": "a195c391-6f9e-466b-a05d-3f64f36b1f27",
            "~thread": {
                "thid": "a3b9187d-b9fe-4ae4-8216-7d3de4c5fb5f",
                "pthid": "31994d69-63b9-4fcb-a3c4-b25883b13587"
            },
            "did_doc~attach": {
                "@id": "b0917b43-1b03-468e-8cca-c16210a4a974",
                "mime-type": "application/json",
                "data": {
                    "base64": "eyJAY29ud...wMzAifV19",
                    "jws": {
                        "header": {
                            "kid": "did:key:z6MkfBLA5kbwFsmt96rLrwqgod3aBjGKEQXKzFajWSnpk6ML"
                        },
                        "protected": "eyJhbGc...bnBrNk1MIn19",
                        "signature": "iJYjrt_...StEhcyJ9QROBA"
                    }
                }
            },
            "did": "4yUMBgNGLcCGLAipq9zZox"
        }

        // Attached is Faber"s Did Document ============================================================================
        //
        2023-01-20 13:34:15,645 acapy02
        {
            "@context": "https://w3id.org/did/v1",
            "id": "did:sov:4yUMBgNGLcCGLAipq9zZox",
            "publicKey": [
                {
                    "id": "did:sov:4yUMBgNGLcCGLAipq9zZox#1",
                    "type": "Ed25519VerificationKey2018",
                    "controller": "did:sov:4yUMBgNGLcCGLAipq9zZox",
                    "publicKeyBase58": "3AcfDufvBCKp6TSWZzRHdRRYH4SYKRkfbkMbs7Qu4qzc"
                }
            ],
            "authentication": [
                {
                    "type": "Ed25519SignatureAuthentication2018",
                    "publicKey": "did:sov:4yUMBgNGLcCGLAipq9zZox#1"
                }
            ],
            "service": [
                {
                    "id": "did:sov:4yUMBgNGLcCGLAipq9zZox;indy",
                    "type": "IndyAgent",
                    "priority": 0,
                    "recipientKeys": [
                        "3AcfDufvBCKp6TSWZzRHdRRYH4SYKRkfbkMbs7Qu4qzc"
                    ],
                    "serviceEndpoint": "http://192.168.0.10:8030"
                }
            ]
        }

        // Faber receives DidEx Complete ===============================================================================
        //
        2023-01-20 13:34:15,744 acapy01
        {
            "@type": "https://didcomm.org/didexchange/1.0/complete",
            "@id": "129c4f18-dac0-4d77-bf9a-15d7af2177d3",
            "~thread": {
                "thid": "a3b9187d-b9fe-4ae4-8216-7d3de4c5fb5f",
                "pthid": "31994d69-63b9-4fcb-a3c4-b25883b13587"
            }
        }

        // Faber receives a Trust Ping =================================================================================
        //
        2023-01-20 13:34:15,760 acapy01
        {
            "@type": "https://didcomm.org/trust_ping/1.0/ping",
            "@id": "5cf45e53-4a5c-4827-801d-287cfb1121f0",
            "response_requested": True
        }

        // Alice receives a Trust Ping Response ========================================================================
        //
        2023-01-20 13:34:15,955 acapy02
        {
            "@type": "https://didcomm.org/trust_ping/1.0/ping_response",
            "@id": "5e49588e-fc78-4ee8-a3fb-d8dc1dcda4bf",
            "~thread": {
                "thid": "5cf45e53-4a5c-4827-801d-287cfb1121f0"
            }
        }
        */
    }
}
