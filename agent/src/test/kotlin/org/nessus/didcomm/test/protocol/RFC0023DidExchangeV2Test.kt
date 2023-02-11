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
package org.nessus.didcomm.test.protocol

import id.walt.common.prettyPrint
import id.walt.crypto.KeyAlgorithm
import mu.KotlinLogging
import org.didcommx.didcomm.model.PackEncryptedParams
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.protocols.routing.PROFILE_DIDCOMM_V2
import org.junit.jupiter.api.Test
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.DidExchangeMessageV2
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocolV2.Companion.RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V2
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE_V2
import org.nessus.didcomm.service.RFC0048_TRUST_PING_V1
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V2
import org.nessus.didcomm.test.AbstractDidCommTest
import org.nessus.didcomm.test.Acme
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.test.NESSUS_OPTIONS_01
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.wallet.NessusWalletPlugin.Companion.getNessusEndpointUrl
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class RFC0023DidExchangeV2Test: AbstractDidCommTest() {
    val log = KotlinLogging.logger {}

    @Test
    fun testDidExchangeV2() {

        startNessusEndpoint(NESSUS_OPTIONS_01).use {

            val acme = Wallet.Builder(Acme.name)
                .build()

            val alice = Wallet.Builder(Alice.name)
                .build()

            try {

                /**
                 * Inviter (Acme) creates an Out-of-Band Invitation
                 * Invitee (Alice) receives and accepts the Invitation
                 * Requester (Alice) send the DidEx Request
                 * Responder (Acme) accepts the DidEx Request and sends a Response
                 * Requester (Alice) sends the DidEx Complete message
                 * Requester (Alice) sends a Trust Ping
                 * Responder (Acme) sends a Trust Ping Response
                 */

                val mex = MessageExchange()

                    .withProtocol(RFC0434_OUT_OF_BAND_V2)
                    .createOutOfBandInvitation(acme, mapOf(
                        "goal_code" to "issue-vc",
                        "goal" to "Employment credential with Acme"))
                    .receiveOutOfBandInvitation(alice)

                    .withProtocol(RFC0023_DIDEXCHANGE_V2)
                    .sendDidExchangeRequest(alice)
                    .awaitDidExchangeResponse()
                    .sendDidExchangeComplete()

                    .withProtocol(RFC0048_TRUST_PING_V1)
                    .sendTrustPing()
                    .awaitTrustPingResponse()

                    .getMessageExchange()

                val aliceAcme = mex.getConnection()
                val acmeAlice = acme.findConnection{ it.myVerkey == aliceAcme.theirVerkey }

                verifyConnection(alice, aliceAcme)
                verifyConnection(acme, acmeAlice)

            } finally {
                removeWallet(Alice.name)
                removeWallet(Acme.name)
            }
        }
    }

    @Test
    fun testEncryptedDidExRequest() {

        val acmeDid = didService.createDid(DidMethod.KEY, KeyAlgorithm.EdDSA_Ed25519, seed = Acme.seed.toByteArray())
        val aliceDid = didService.createDid(DidMethod.KEY, KeyAlgorithm.EdDSA_Ed25519, seed = Alice.seed.toByteArray())
        val endpointUrl = getNessusEndpointUrl(NESSUS_OPTIONS_01)

        val acmeDidDoc = diddocV2Service.createDidDocument(acmeDid, endpointUrl)
        log.info { "Acme ${acmeDidDoc.prettyPrint()}" }

        val aliceDidDoc = diddocV2Service.createDidDocument(aliceDid, endpointUrl)
        log.info { "Alice ${aliceDidDoc.prettyPrint()}" }

        val message = DidExchangeMessageV2.Builder(
            id = "0123Request",
            type = RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V2,
            thid = "0123Request",
            pthid = "0123Invi")
            .to(listOf(acmeDid.qualified))
            .accept(listOf(PROFILE_DIDCOMM_V2))
            .build().toMessage()

        val packResult = didComm.packEncrypted(
            PackEncryptedParams.builder(message, acmeDid.qualified)
                .signFrom(aliceDid.qualified)
                .from(aliceDid.qualified)
                .build()
        )
        val packedMessage = packResult.packedMessage
        val serviceEndpoint = packResult.serviceMetadata?.serviceEndpoint ?: ""
        log.info { "Sending to $serviceEndpoint - ${packedMessage.prettyPrint()}" }

        val unpackResult = didComm.unpack(
            UnpackParams.Builder(packedMessage)
                .secretResolver(secretResolver)
                .build()
        )
        val unpackedMessage = unpackResult.message
        log.info { "Unpacked\n${unpackedMessage.encodeJson(true)}" }

        assertEquals(message, unpackResult.message)
        with(unpackResult.metadata) {
            assertTrue { encrypted }
            assertTrue { authenticated }
            assertTrue { nonRepudiation }
            assertFalse { anonymousSender }
            assertFalse { reWrappedInForward }
        }
    }


    private fun verifyConnection(wallet: Wallet, pcon: Connection?) {
        requireNotNull(pcon) { "No connection" }

        val aliceMex = MessageExchange.findByVerkey(pcon.myVerkey)
        aliceMex.showMessages(wallet.name)

        log.info { "${wallet.name}'s Connection: ${pcon.prettyPrint()}" }
        assertEquals(ConnectionState.ACTIVE, pcon.state)

        val myModelInvi = wallet.findInvitation { i -> i.invitationKey() == pcon.invitationKey }
        assertEquals(pcon.invitationKey, myModelInvi?.invitationKey())

        val myModelCon = wallet.findConnection { c -> c.id == pcon.id }
        assertEquals(pcon, myModelCon)

        val myModelDid = wallet.findDid { d -> d.verkey == pcon.myVerkey }
        assertEquals(pcon.myDid, myModelDid)
    }
}

