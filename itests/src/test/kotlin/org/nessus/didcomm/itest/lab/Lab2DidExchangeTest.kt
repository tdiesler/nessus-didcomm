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
import id.walt.crypto.KeyAlgorithm
import org.junit.jupiter.api.Test
import org.nessus.didcomm.agent.AriesAgent.Companion.awaitConnectionRecord
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.itest.ACAPY_OPTIONS_02
import org.nessus.didcomm.itest.AbstractIntegrationTest
import org.nessus.didcomm.itest.Alice
import org.nessus.didcomm.itest.Faber
import org.nessus.didcomm.itest.NESSUS_OPTIONS_01
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageListener
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope.Companion.RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocol.Companion.MESSAGE_TYPE_RFC0023_DID_EXCHANGE_REQUEST
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocol.Companion.MESSAGE_TYPE_RFC0023_DID_EXCHANGE_RESPONSE
import org.nessus.didcomm.service.Invitation
import org.nessus.didcomm.service.PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE
import org.nessus.didcomm.service.toDidKey
import org.nessus.didcomm.util.decodeBase64UrlStr
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.matches
import org.nessus.didcomm.util.prettyGson
import org.nessus.didcomm.util.selectJson
import org.nessus.didcomm.util.trimJson
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.DidMethod
import org.nessus.didcomm.wallet.StorageType
import org.nessus.didcomm.wallet.Wallet
import java.util.*
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit
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
class Lab2DidExchangeTest : AbstractIntegrationTest() {

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

        try {

            /**
             * Inviter (Faber) creates an Out-of-Band Invitation
             */

            val invitation = run {
                val req = """
                {
                  "accept": [ "didcomm/v2" ],
                  "alias": "Faber/Alice",
                  "handshake_protocols": [ "https://didcomm.org/didexchange/1.0" ],
                  "my_label": "Invitation for Alice",
                  "protocol_version": "1.1",
                  "use_public_did": false
                }
                """.trimJson()
                val res = faberClient.adminPost(
                    "/out-of-band/create-invitation", req, mapOf(
                        "auto_accept" to true)
                )

                check(res.isSuccessful) { "Call failed with ${res.code} ${res.message}" }
                val body = res.body?.string()
                val invitationJson = body?.selectJson("invitation")
                gson.fromJson(invitationJson, Invitation::class.java)
            }
            val invitationId = invitation.atId

            /**
             * Invitee (Alice) receives the Invitation
             */

            run {
                val req = gson.toJson(invitation)
                val res = aliceClient.adminPost(
                    "/out-of-band/receive-invitation", req, mapOf(
                        "use_existing_connection" to false,
                        "auto_accept" to true)
                )

                check(res.isSuccessful) { "Call failed with ${res.code} ${res.message}" }
            }

            /**
             * Invitee (Alice) awaits her active Connection
             */

            val inviteeConnection = awaitConnectionRecord(alice) {
                it.invitationMsgId == invitationId && it.stateIsActive()
            }
            checkNotNull(inviteeConnection) {"${alice.alias} has no connection record in state 'active'"}
            log.info {"${alice.alias} connection: ${inviteeConnection.state}"}
            log.info("${alice.alias}: {}", prettyGson.toJson(inviteeConnection))

            /**
             * Inviter (Faber) awaits it's active Connection
             */

            val inviterConnection = awaitConnectionRecord(faber) {
                it.invitationMsgId == invitationId && it.stateIsActive()
            }
            checkNotNull(inviterConnection) {"${faber.alias} has no connection record in state 'active'"}
            log.info {"${faber.alias} connection: ${inviterConnection.state}"}
            log.info("${faber.alias}: {}", prettyGson.toJson(inviterConnection))

        } finally {
            log.info { "Done ".padEnd(180, '=') }
            faber.removeConnections()
            removeWallet(Alice.name)
        }
    }

    @Test
    fun test_FaberAcapy_invites_AliceAcapy_LogEntries() {

        // docker compose logs -f acapy01 2> /dev/null | grep Expanded
        // docker compose logs -f acapy02 2> /dev/null | grep Expanded

        """
            acapy01  | 2023-01-19 07:23:38,289 aries_cloudagent.transport.pack_format DEBUG Expanded message: {'@type': 'https://didcomm.org/didexchange/1.0/request', '@id': '29d871eb-b74a-477a-a6dd-02c9b0d8ca2b', '~thread': {'thid': '29d871eb-b74a-477a-a6dd-02c9b0d8ca2b', 'pthid': 'f51cf857-73c6-46a5-9000-0d2e132d0ed4'}, 'did_doc~attach': {'@id': 'b98ba48d-0f95-4c69-b7e9-116edac2d74c', 'mime-type': 'application/json', 'data': {'base64': 'eyJAY29udGV4dCI6ICJodHRwczovL3czaWQub3JnL2RpZC92MSIsICJpZCI6ICJkaWQ6c292OlBwZG1FTnZNczM3a3NQNUxoNjQxcFkiLCAicHVibGljS2V5IjogW3siaWQiOiAiZGlkOnNvdjpQcGRtRU52TXMzN2tzUDVMaDY0MXBZIzEiLCAidHlwZSI6ICJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCIsICJjb250cm9sbGVyIjogImRpZDpzb3Y6UHBkbUVOdk1zMzdrc1A1TGg2NDFwWSIsICJwdWJsaWNLZXlCYXNlNTgiOiAiRFNSZzlqVWVDWDdtR0o1UFFOUVhvRVdWZnVxY0VlRHc5MTNqeGh2VWJNYWYifV0sICJhdXRoZW50aWNhdGlvbiI6IFt7InR5cGUiOiAiRWQyNTUxOVNpZ25hdHVyZUF1dGhlbnRpY2F0aW9uMjAxOCIsICJwdWJsaWNLZXkiOiAiZGlkOnNvdjpQcGRtRU52TXMzN2tzUDVMaDY0MXBZIzEifV0sICJzZXJ2aWNlIjogW3siaWQiOiAiZGlkOnNvdjpQcGRtRU52TXMzN2tzUDVMaDY0MXBZO2luZHkiLCAidHlwZSI6ICJJbmR5QWdlbnQiLCAicHJpb3JpdHkiOiAwLCAicmVjaXBpZW50S2V5cyI6IFsiRFNSZzlqVWVDWDdtR0o1UFFOUVhvRVdWZnVxY0VlRHc5MTNqeGh2VWJNYWYiXSwgInNlcnZpY2VFbmRwb2ludCI6ICJodHRwOi8vMTkyLjE2OC4wLjEwOjgwNDAifV19', 'jws': {'header': {'kid': 'did:key:z6Mkrtgijyj5Y4cENnv65wNNeL4VVV7TeXUHq1xfnytVWaN3'}, 'protected': 'eyJhbGciOiAiRWREU0EiLCAia2lkIjogImRpZDprZXk6ejZNa3J0Z2lqeWo1WTRjRU5udjY1d05OZUw0VlZWN1RlWFVIcTF4Zm55dFZXYU4zIiwgImp3ayI6IHsia3R5IjogIk9LUCIsICJjcnYiOiAiRWQyNTUxOSIsICJ4IjogInVNLXAyTjdGTTdnZzVxa0N2WFZDVFVCZzZ6UHRPVktMMmxqNVlHRk5mQkEiLCAia2lkIjogImRpZDprZXk6ejZNa3J0Z2lqeWo1WTRjRU5udjY1d05OZUw0VlZWN1RlWFVIcTF4Zm55dFZXYU4zIn19', 'signature': '-LbC1mY1zUdNHJ5KdVboAdInSj9RgPYNLLvLPLTrr9pwi6zwWVbmh6wpkDzoURyONKGQdstj4YS2fp4pvJwZBA'}}}, 'did': 'PpdmENvMs37ksP5Lh641pY', 'label': 'Aries Cloud Agent'}
            acapy01  | 2023-01-19 07:23:38,765 aries_cloudagent.transport.pack_format DEBUG Expanded message: {'@type': 'https://didcomm.org/didexchange/1.0/complete', '@id': '3af78cc4-9076-466e-8dd0-8606d99ac319', '~thread': {'thid': '29d871eb-b74a-477a-a6dd-02c9b0d8ca2b', 'pthid': 'f51cf857-73c6-46a5-9000-0d2e132d0ed4'}}
            acapy01  | 2023-01-19 07:23:38,779 aries_cloudagent.transport.pack_format DEBUG Expanded message: {'@type': 'https://didcomm.org/trust_ping/1.0/ping', '@id': 'e84001cf-ec77-4716-8319-69c98763081a', 'response_requested': True}
            
            acapy02  | 2023-01-19 07:23:38,686 aries_cloudagent.transport.pack_format DEBUG Expanded message: {'@type': 'https://didcomm.org/didexchange/1.0/response', '@id': '971a30c9-5cbb-431a-b47d-8a42eaacfaeb', '~thread': {'thid': '29d871eb-b74a-477a-a6dd-02c9b0d8ca2b', 'pthid': 'f51cf857-73c6-46a5-9000-0d2e132d0ed4'}, 'did_doc~attach': {'@id': '6a37d950-bd7e-4076-b634-b0cf7dfecc64', 'mime-type': 'application/json', 'data': {'base64': 'eyJAY29udGV4dCI6ICJodHRwczovL3czaWQub3JnL2RpZC92MSIsICJpZCI6ICJkaWQ6c292OlRCZFk1alNoMWl2YzVFQk5kcjdvU2MiLCAicHVibGljS2V5IjogW3siaWQiOiAiZGlkOnNvdjpUQmRZNWpTaDFpdmM1RUJOZHI3b1NjIzEiLCAidHlwZSI6ICJFZDI1NTE5VmVyaWZpY2F0aW9uS2V5MjAxOCIsICJjb250cm9sbGVyIjogImRpZDpzb3Y6VEJkWTVqU2gxaXZjNUVCTmRyN29TYyIsICJwdWJsaWNLZXlCYXNlNTgiOiAiRkdodFA0QUFlUEd6Skd2Ykc0YnVDQkJqNUs0WWI2bW9iWjd5TkFzaU5UQlQifV0sICJhdXRoZW50aWNhdGlvbiI6IFt7InR5cGUiOiAiRWQyNTUxOVNpZ25hdHVyZUF1dGhlbnRpY2F0aW9uMjAxOCIsICJwdWJsaWNLZXkiOiAiZGlkOnNvdjpUQmRZNWpTaDFpdmM1RUJOZHI3b1NjIzEifV0sICJzZXJ2aWNlIjogW3siaWQiOiAiZGlkOnNvdjpUQmRZNWpTaDFpdmM1RUJOZHI3b1NjO2luZHkiLCAidHlwZSI6ICJJbmR5QWdlbnQiLCAicHJpb3JpdHkiOiAwLCAicmVjaXBpZW50S2V5cyI6IFsiRkdodFA0QUFlUEd6Skd2Ykc0YnVDQkJqNUs0WWI2bW9iWjd5TkFzaU5UQlQiXSwgInNlcnZpY2VFbmRwb2ludCI6ICJodHRwOi8vMTkyLjE2OC4wLjEwOjgwMzAifV19', 'jws': {'header': {'kid': 'did:key:z6MkusbryWJE9BeqWuDYgYQAahodhJ5BKc727h9HnXYhg97E'}, 'protected': 'eyJhbGciOiAiRWREU0EiLCAia2lkIjogImRpZDprZXk6ejZNa3VzYnJ5V0pFOUJlcVd1RFlnWVFBYWhvZGhKNUJLYzcyN2g5SG5YWWhnOTdFIiwgImp3ayI6IHsia3R5IjogIk9LUCIsICJjcnYiOiAiRWQyNTUxOSIsICJ4IjogIjVSdW1naUtfZXUtRVJHX0lYNEZTWE1tSTJhRFZBR1hmRHNrVW9tYnFnNEUiLCAia2lkIjogImRpZDprZXk6ejZNa3VzYnJ5V0pFOUJlcVd1RFlnWVFBYWhvZGhKNUJLYzcyN2g5SG5YWWhnOTdFIn19', 'signature': 'kKy-PeEkBpErStdz-ajqB1KrdTJoa-A_S6eiajGSqtNvS1PJoClOXtx9yhIk3ikq5NO9bpN_MGjm8WPrCB8wAA'}}}, 'did': 'TBdY5jSh1ivc5EBNdr7oSc'}
            acapy02  | 2023-01-19 07:23:38,989 aries_cloudagent.transport.pack_format DEBUG Expanded message: {'@type': 'https://didcomm.org/trust_ping/1.0/ping_response', '@id': '982b3d50-8d5c-4531-8148-1ed3374e5b8b', '~thread': {'thid': 'e84001cf-ec77-4716-8319-69c98763081a'}}
        """.trimIndent().lines()
            .filter { it.isNotEmpty() }
            .filter { it.contains("DEBUG Expanded message") }
            .map {
                val toks = it.split(' ')
                val agent = toks[0]
                val tstamp = "${toks[3]} ${toks[4]}"
                val idx = it.indexOf(": {") + 2
                val msg = it.substring(idx)
                Pair(tstamp, Pair(agent, msg))
            }.sortedBy { it.first }
            .forEach {
                val tstamp = it.first
                val agent = it.second.first
                val msg = it.second.second
                log.info { "$tstamp $agent ${msg.prettyPrint()}" }

                val diddoc64 = msg.selectJson("did_doc~attach.data.base64")
                diddoc64?.run {
                    val diddoc = diddoc64.decodeBase64UrlStr()
                    log.info { "Did Document: ${diddoc.prettyPrint()}" }
                }
            }
    }

    @Test
    fun test_FaberAcapy_invites_AliceNessus() {

        val faber = getWalletByAlias(Faber.name) ?: fail("No Faber")

        val alice = Wallet.Builder(Alice.name)
            .options(NESSUS_OPTIONS_01)
            .agentType(AgentType.NESSUS)
            .storageType(StorageType.IN_MEMORY)
            .build()

        val faberClient = faber.walletClient() as AriesClient

        val mex = MessageExchange()
        val listener: MessageListener = { epm ->
            val contentType = epm.headers["Content-Type"] as? String
            checkNotNull(contentType) { "No 'Content-Type' header"}
            if (contentType == "$RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE") {
                val envelope = mex
                    .withProtocol(PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE)
                    .unpackRFC0019Envelope(epm.bodyAsJson)?.first
                if (envelope == null) {
                    log.warn { "Message recipient unknown" }
                } else {
                    val atType = envelope.selectJson("@type")
                    if (atType == MESSAGE_TYPE_RFC0023_DID_EXCHANGE_RESPONSE) {
                        //didexRequestFuture.complete(envelope)
                    }
                }
            }
        }

        try {
            endpointService.startEndpoint(alice, listener).use {

                /**
                 * Inviter (Faber) creates an Out-of-Band Invitation
                 */

                val invitation = run {
                    val req = """
                {
                  "accept": [ "didcomm/v2" ],
                  "alias": "Faber/Alice",
                  "handshake_protocols": [ "https://didcomm.org/didexchange/1.0" ],
                  "my_label": "Invitation for Alice",
                  "protocol_version": "1.1",
                  "use_public_did": false
                }
                """.trimJson()
                    val res = faberClient.adminPost(
                        "/out-of-band/create-invitation", req, mapOf(
                            "auto_accept" to true)
                    )

                    check(res.isSuccessful) { "Call failed with ${res.code} ${res.message}" }
                    val body = res.body?.string()
                    val invitationJson = body?.selectJson("invitation")
                    gson.fromJson(invitationJson, Invitation::class.java)
                }

                /**
                 * Invitee (Alice) receives the Invitation
                 */

                val invitationId = invitation.atId
                val faberDid = Did.fromSpec(invitation.services[0].recipientKeys[0])
                val faberServiceEndpoint = invitation.services[0].serviceEndpoint

                /**
                 * Invitee (Alice) creates a DidEx Request
                 */

                val didexRequestId = "${UUID.randomUUID()}"
                val aliceDid = didService.createDid(DidMethod.SOV, KeyAlgorithm.EdDSA_Ed25519)

                val aliceDidDoc = """
                {
                    "@context": "https://w3id.org/did/v1",
                    "id": "${aliceDid.qualified}",
                    "publicKey": [
                        {
                            "id": "${aliceDid.qualified}#1",
                            "type": "Ed25519VerificationKey2018",
                            "controller": "${aliceDid.qualified}",
                            "publicKeyBase58": "${aliceDid.verkey}"
                        }
                    ],
                    "authentication": [
                        {
                            "type": "Ed25519SignatureAuthentication2018",
                            "publicKey": "${aliceDid.qualified}#1"
                        }
                    ],
                    "service": [
                        {
                            "id": "${aliceDid.qualified};memory",
                            "type": "NessusAgent",
                            "priority": 0,
                            "recipientKeys": [
                                "${aliceDid.verkey}"
                            ],
                            "serviceEndpoint": "${alice.endpointUrl}"
                        }
                    ]
                }
                """.trimJson()

                log.info { "Invitee DidDoc: ${aliceDidDoc.prettyPrint()}" }

                val aliceDidDocAttach = diddocService.createAttachment(aliceDidDoc, aliceDid)

                val didexRequest = """
                {
                    "@type": "$MESSAGE_TYPE_RFC0023_DID_EXCHANGE_REQUEST",
                    "@id": "$didexRequestId",
                    "~thread": {
                        "thid": "$didexRequestId",
                        "pthid": "$invitationId"
                    },
                    "did_doc~attach": $aliceDidDocAttach,
                    "did": "${aliceDid.id}",
                    "label": "Nessus Agent"
                }
                """.trimJson()
                log.info("DidEx Request: ${didexRequest.prettyPrint()}")

                val packedDidExRequest = mex
                    .withProtocol(PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE)
                    .packRFC0019Envelope(didexRequest, aliceDid, faberDid)
                log.info { "Packed: ${packedDidExRequest.prettyPrint()}"}

                run {
                    val res = faberClient.post(faberServiceEndpoint, packedDidExRequest, headers = mapOf(
                        "Content-Type" to "$RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE"
                    ))
                    check(res.isSuccessful) { "Call failed with ${res.code} ${res.message}" }
                }
            }
        } finally {
            log.info { "Done ".padEnd(180, '=') }
            faber.removeConnections()
            removeWallet(Alice.name)
        }
    }

    @Test
    fun test_AliceNessus_invites_FaberAcapy() {

        val faber = getWalletByAlias(Faber.name) ?: fail("No Faber")

        val alice = Wallet.Builder(Alice.name)
            .options(NESSUS_OPTIONS_01)
            .agentType(AgentType.NESSUS)
            .storageType(StorageType.IN_MEMORY)
            .build()

        val faberClient = faber.walletClient() as AriesClient

        val didexRequestFuture = CompletableFuture<String>()
        val didexCompleteFuture = CompletableFuture<String>()

        val mex = MessageExchange()
        val listener: MessageListener = { epm ->
            val contentType = epm.headers["Content-Type"] as? String
            checkNotNull(contentType) { "No 'Content-Type' header"}
            if (RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE.matches(contentType)) {
                val envelope = mex
                    .withProtocol(PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE)
                    .unpackRFC0019Envelope(epm.bodyAsJson)?.first
                if (envelope == null) {
                    log.warn { "Message recipient unknown" }
                } else {
                    val atType = envelope.selectJson("@type")
                    if (atType == MESSAGE_TYPE_RFC0023_DID_EXCHANGE_REQUEST) {
                        didexRequestFuture.complete(envelope)
                    }
                }
            }
        }

        try {

            endpointService.startEndpoint(alice, listener).use {

                /**
                 * Inviter (Alice) creates an Out-of-Band Invitation
                 */
                val aliceDid = didService.createDid(DidMethod.SOV, KeyAlgorithm.EdDSA_Ed25519)
                val aliceDidKey = keyStore.load(aliceDid.verkey).toDidKey()
                val invitationId = "${UUID.randomUUID()}"
                val invitation = """
                {
                  "@id": "$invitationId",
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
                        "${aliceDidKey.qualified}"
                      ],
                      "serviceEndpoint": "${alice.endpointUrl}",
                      "type": "did-communication"
                    }
                  ]
                }
                """.trimJson()

                /**
                 * Invitee (Faber) receives the Invitation (somehow)
                 * and sends an encrypted DidEx Request
                 */

                run {
                    val res = faberClient.adminPost(
                        "/out-of-band/receive-invitation", invitation, mapOf(
                            "use_existing_connection" to false,
                            "auto_accept" to true)
                    )
                    check(res.isSuccessful) { "Call failed with ${res.code} ${res.message}" }
                }

                /**
                 * Inviter (Alice) receives an encrypted DidEx Request
                 */

                // Get the DidEx Request from a Future
                val didexRequest = didexRequestFuture.get(10, TimeUnit.SECONDS)

                val didexRequestId = didexRequest.selectJson("@id")
                val attachedDidDoc = didexRequest.selectJson("did_doc~attach")
                checkNotNull(attachedDidDoc) { "No 'did_doc~attach' in DidEx Request"}
                val faberDidDoc = diddocService.extractFromAttachment(attachedDidDoc)
                val faberVerkey = faberDidDoc.publicKey[0].publicKeyBase58
                val faberDid = Did.fromSpec(faberDidDoc.publicKey[0].controller, faberVerkey)
                val faberServiceEndpoint = faberDidDoc.service[0].serviceEndpoint

                /**
                 * Inviter (Alice) sends an encrypted DidEx Response
                 */

                val aliceDidDoc = """
                {
                    "@context": "https://w3id.org/did/v1",
                    "id": "${aliceDid.qualified}",
                    "publicKey": [
                        {
                            "id": "${aliceDid.qualified}#1",
                            "type": "Ed25519VerificationKey2018",
                            "controller": "${aliceDid.qualified}",
                            "publicKeyBase58": "${aliceDid.verkey}"
                        }
                    ],
                    "authentication": [
                        {
                            "type": "Ed25519SignatureAuthentication2018",
                            "publicKey": "${aliceDid.qualified}#1"
                        }
                    ],
                    "service": [
                        {
                            "id": "${aliceDid.qualified};memory",
                            "type": "NessusAgent",
                            "priority": 0,
                            "recipientKeys": [
                                "${aliceDid.verkey}"
                            ],
                            "serviceEndpoint": "${alice.endpointUrl}"
                        }
                    ]
                }
                """.trimJson()
                log.info { "Inviter DidDoc: ${aliceDidDoc.prettyPrint()}" }

                val didexResponse = """
                {
                    '@type': '$MESSAGE_TYPE_RFC0023_DID_EXCHANGE_RESPONSE',
                    '@id': '${UUID.randomUUID()}',
                    '~thread': {
                        'thid': '$didexRequestId'
                    },
                    'did_doc~attach': ${diddocService.createAttachment(aliceDidDoc, aliceDid)},
                    'did': '${aliceDid.id}'
                }                    
                """.trimJson()
                log.info { "DidEx Response: ${didexResponse.prettyPrint()}" }

                val packedDidExResponse = mex
                    .withProtocol(PROTOCOL_URI_RFC0019_ENCRYPTED_ENVELOPE)
                    .packRFC0019Envelope(didexResponse, aliceDid, faberDid)

                run {
                    // https://github.com/hyperledger/aries-cloudagent-python/issues/2083
                    val res = faberClient.post(faberServiceEndpoint, packedDidExResponse, headers = mapOf(
                        "Content-Type" to "$RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE"
                    ))
                    check(res.isSuccessful) { "Call failed with ${res.code} ${res.message}" }
                }

                /**
                 * Inviter (Alice) receives a DidEx Complete message
                 */

                // Get the DidEx Request from a Future
                // val didexComplete = didexCompleteFuture.get(10, TimeUnit.SECONDS)

            }

        } finally {
            log.info { "Done ".padEnd(180, '=') }
            faber.removeConnections()
            removeWallet(Alice.name)
        }
    }
}

//        faber.openWebSocket {
//            log.info { "WebSocket ${faber.alias}: ${it.topic}" }
//            log.info { it.payload.sortedJson().prettyPrint() }
//        }
//
//        alice.openWebSocket {
//            log.info { "WebSocket ${alice.alias}: ${it.topic}" }
//            log.info { it.payload.sortedJson().prettyPrint() }
//        }
