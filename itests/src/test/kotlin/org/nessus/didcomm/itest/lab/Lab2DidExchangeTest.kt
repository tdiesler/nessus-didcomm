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
import org.hyperledger.aries.api.out_of_band.CreateInvitationFilter
import org.hyperledger.aries.api.out_of_band.InvitationCreateRequest
import org.junit.jupiter.api.Test
import org.nessus.didcomm.agent.AriesClient
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.itest.AbstractIntegrationTest
import org.nessus.didcomm.itest.Alice
import org.nessus.didcomm.itest.Faber
import org.nessus.didcomm.itest.NESSUS_OPTIONS_01
import org.nessus.didcomm.protocol.EndpointMessage
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.MessageListener
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope.Companion.RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocol.Companion.RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocol.Companion.RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocol.Companion.RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE
import org.nessus.didcomm.protocol.RFC0048TrustPingProtocol.Companion.RFC0048_TRUST_PING_MESSAGE_TYPE_PING
import org.nessus.didcomm.protocol.RFC0048TrustPingProtocol.Companion.RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE
import org.nessus.didcomm.service.RFC0019_ENCRYPTED_ENVELOPE
import org.nessus.didcomm.util.gson
import org.nessus.didcomm.util.matches
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
    fun test_FaberAcapy_invites_AliceNessus() {

        val faber = getWalletByAlias(Faber.name) ?: fail("No Faber")

        val alice = Wallet.Builder(Alice.name)
            .options(NESSUS_OPTIONS_01)
            .agentType(AgentType.NESSUS)
            .storageType(StorageType.IN_MEMORY)
            .build()

        val faberClient = faber.walletClient() as AriesClient
        val faberAutoAccept = true

        val didexResponseFuture = CompletableFuture<String>()
        val trustPingResponseFuture = CompletableFuture<String>()

        val listener: MessageListener = { epm ->
            val contentType = epm.headers["Content-Type"] as? String
            checkNotNull(contentType) { "No 'Content-Type' header"}
            if (RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE.matches(contentType)) {
                val message = getProtocol(RFC0019_ENCRYPTED_ENVELOPE)
                    .unpackEncryptedEnvelope(epm.bodyAsJson)?.message
                if (message != null) {
                    val atType = message.selectJson("@type")
                    if (atType == RFC0023_DIDEXCHANGE_MESSAGE_TYPE_RESPONSE) {
                        didexResponseFuture.complete(message) }
                    else if (atType == RFC0048_TRUST_PING_MESSAGE_TYPE_PING_RESPONSE) {
                        trustPingResponseFuture.complete(message)
                    } else {
                        log.warn { "Unknown message type: $atType" }
                    }
                    MessageExchange(EndpointMessage(message))
                } else {
                    log.warn { "Message recipient unknown" }
                    null
                }
            } else {
                log.warn { "Unknown content type: $contentType" }
                null
            }
        }

        try {

            endpointService.startEndpoint(alice, listener).use {

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

                val faberInvRecord = faberClient.outOfBandCreateInvitation(createInvRequest, createInvFilter).get()
                val invitation = gson.toJson(faberInvRecord.invitation)

                /**
                 * Invitee (Alice) receives the Invitation (somehow)
                 */

                val invitationId = invitation.selectJson("@id") as String
                val faberDid = Did.fromSpec(invitation.selectJson("services[0].recipientKeys[0]") as String)
                val faberServiceEndpoint = invitation.selectJson("services[0].serviceEndpoint") as String

                /**
                 * Invitee (Alice) manually accepts the Invitation and sends a DidEx Request
                 */

                val aliceDid = didService.createDid(DidMethod.SOV)

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
                log.info { "Alice's Did Document: ${aliceDidDoc.prettyPrint()}" }

                val aliceDidDocAttach = diddocService.createAttachment(aliceDidDoc, aliceDid)

                val didexRequestId = "${UUID.randomUUID()}"
                val didexRequest = """
                {
                    "@type": "$RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST",
                    "@id": "$didexRequestId",
                    "~thread": {
                        "thid": "$didexRequestId",
                        "pthid": "$invitationId"
                    },
                    "label": "Accept Faber/Alice",
                    "did": "${aliceDid.id}",
                    "did_doc~attach": $aliceDidDocAttach
                }
                """.trimJson()

                val packedDidExRequest = getProtocol(RFC0019_ENCRYPTED_ENVELOPE)
                    .packEncryptedEnvelope(didexRequest, aliceDid, faberDid)

                run {
                    val res = httpClient.post(
                        faberServiceEndpoint, packedDidExRequest, headers = mapOf(
                            "Content-Type" to "$RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE"
                        )
                    )
                    check(res.isSuccessful) { "Call failed with ${res.code} ${res.message}" }
                }

                /**
                 * Responder (Faber) accepts the DidEx Request and sends a Response
                 */

                val didexResponse = didexResponseFuture.get(10, TimeUnit.SECONDS)
                val faberDidDocAttach = didexResponse.selectJson("did_doc~attach") as? String
                checkNotNull(faberDidDocAttach) { "No attached Did Document in DidEx Response" }

                diddocService.extractFromAttachment(faberDidDocAttach, faberDid)

                /**
                 * Requester (Alice) sends the DidEx Complete message
                 */

                val didexComplete = """
                {
                    "@type": "$RFC0023_DIDEXCHANGE_MESSAGE_TYPE_COMPLETE",
                    "@id": "${UUID.randomUUID()}",
                    "~thread": {
                        "thid": "$didexRequestId",
                        "pthid": "$invitationId"
                    }
                }
                """.trimJson()

                val packedDidExComplete = getProtocol(RFC0019_ENCRYPTED_ENVELOPE)
                    .packEncryptedEnvelope(didexComplete, aliceDid, faberDid)

                run {
                    val res = httpClient.post(
                        faberServiceEndpoint, packedDidExComplete, headers = mapOf(
                            "Content-Type" to "$RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE"
                        )
                    )
                    check(res.isSuccessful) { "Call failed with ${res.code} ${res.message}" }
                }

                /**
                 * Requester (Alice) sends a Trust Ping
                 */

                val trustPing = """
                {
                    "@type": "$RFC0048_TRUST_PING_MESSAGE_TYPE_PING",
                    "@id": "${UUID.randomUUID()}",
                    "response_requested": True
                }
                """.trimJson()

                val packedTrustPing = getProtocol(RFC0019_ENCRYPTED_ENVELOPE)
                    .packEncryptedEnvelope(trustPing, aliceDid, faberDid)

                run {
                    val res = httpClient.post(
                        faberServiceEndpoint, packedTrustPing, headers = mapOf(
                            "Content-Type" to "$RFC0019_ENCRYPTED_ENVELOPE_MEDIA_TYPE"
                        )
                    )
                    check(res.isSuccessful) { "Call failed with ${res.code} ${res.message}" }
                }

                /**
                 * Responder (Faber) sends a Trust Ping Response
                 */

                trustPingResponseFuture.get(10, TimeUnit.SECONDS)
            }

        } finally {
            log.info { "Done ".padEnd(180, '=') }
            faber.removeConnections()
            removeWallet(Alice.name)
        }
    }
}
