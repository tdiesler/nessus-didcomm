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
package org.nessus.didcomm.itest

import id.walt.common.prettyPrint
import io.kotest.core.annotation.EnabledIf
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.nessus.didcomm.model.AgentType
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionState.ACTIVE
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE_V1
import org.nessus.didcomm.service.RFC0048_TRUST_PING_V1
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND_V1


/**
 * Aries RFC 0434: Out-of-Band Protocol 1.1
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0434-outofband
 *
 * Aries RFC 0023: DID Exchange Protocol 1.0
 * https://github.com/hyperledger/aries-rfcs/tree/main/features/0023-did-exchange
 */
@EnabledIf(AcaPyOnlyCondition::class)
class RFC0023DidExchangeV1Test : AbstractIntegrationTest() {
    private val log = KotlinLogging.logger {}

    @Test
    fun test_FaberAcapy_invites_AliceNessus() {

        startNessusEndpoint(NESSUS_OPTIONS_01).use {

            /**
             * Create the Wallets
             */

            val faber = Wallet.Builder(Faber.name)
                .options(ACAPY_OPTIONS_01)
                .agentType(AgentType.ACAPY)
                .build()

            val alice = Wallet.Builder(Alice.name)
                .options(NESSUS_OPTIONS_01)
                .agentType(AgentType.NESSUS)
                .build()

            try {

                /**
                 * Inviter (Faber) creates an Out-of-Band Invitation
                 * Invitee (Alice) receives and accepts the Invitation
                 * Requester (Alice) send the DidEx Request
                 * Responder (Faber) accepts the DidEx Request and sends a Response
                 * Requester (Alice) sends the DidEx Complete message
                 * Requester (Alice) sends a Trust Ping
                 * Responder (Faber) sends a Trust Ping Response
                 */

                val mex = MessageExchange()
                    .withProtocol(RFC0434_OUT_OF_BAND_V1)
                    .createOutOfBandInvitation(faber, "Faber invites Alice")
                    .receiveOutOfBandInvitation(alice)

                    .withProtocol(RFC0023_DIDEXCHANGE_V1)
                    .sendDidExchangeRequest(alice)
                    .awaitDidExchangeResponse()
                    .sendDidExchangeComplete()

                    .withProtocol(RFC0048_TRUST_PING_V1)
                    .sendTrustPing()
                    .awaitTrustPingResponse()

                    .getMessageExchange()

                val aliceFaber = mex.getConnection()
                val faberAlice = faber.findConnection { it.myVerkey == aliceFaber.theirVerkey }

                verifyConnection(alice, aliceFaber)

                verifyConnection(faber, faberAlice)

            } finally {
                removeWallet(alice)
                removeWallet(faber)
            }
        }
    }

    @Test
    fun test_FaberNessus_invites_AliceNessus() {

        startNessusEndpoint(NESSUS_OPTIONS_01).use {

            /**
             * Create the Wallets
             */

            val acme = Wallet.Builder(Faber.name)
                .options(NESSUS_OPTIONS_01)
                .agentType(AgentType.NESSUS)
                .build()

            val alice = Wallet.Builder(Alice.name)
                .options(NESSUS_OPTIONS_01)
                .agentType(AgentType.NESSUS)
                .build()

            try {

                /**
                 * Inviter (Faber) creates an Out-of-Band Invitation
                 * Invitee (Alice) receives and accepts the Invitation
                 * Requester (Alice) send the DidEx Request
                 * Responder (Faber) accepts the DidEx Request and sends a Response
                 * Requester (Alice) sends the DidEx Complete message
                 * Requester (Alice) sends a Trust Ping
                 * Responder (Faber) sends a Trust Ping Response
                 */

                val mex = MessageExchange()
                    .withProtocol(RFC0434_OUT_OF_BAND_V1)
                    .createOutOfBandInvitation(acme, "Faber invites Alice")
                    .receiveOutOfBandInvitation(alice)

                    .withProtocol(RFC0023_DIDEXCHANGE_V1)
                    .sendDidExchangeRequest(alice)
                    .awaitDidExchangeResponse()
                    .sendDidExchangeComplete()

                    .withProtocol(RFC0048_TRUST_PING_V1)
                    .sendTrustPing()
                    .awaitTrustPingResponse()

                    .getMessageExchange()

                val aliceFaber = mex.getConnection()
                val acmeAlice = acme.findConnection{ it.myVerkey == aliceFaber.theirVerkey }

                verifyConnection(alice, aliceFaber)
                verifyConnection(acme, acmeAlice)

            } finally {
                removeWallet(alice)
                removeWallet(acme)
            }
        }
    }

    private fun verifyConnection(wallet: Wallet, pcon: Connection?) {
        requireNotNull(pcon) { "No connection" }

        val aliceMex = MessageExchange.findByVerkey(pcon.myVerkey)
        aliceMex.showMessages(wallet.name)

        log.info { "${wallet.name}'s Connection: ${pcon.prettyPrint()}" }
        pcon.state shouldBe ACTIVE

        val myModelInvi = wallet.findInvitation { i -> i.invitationKey() == pcon.invitationKey }
        myModelInvi?.invitationKey() shouldBe pcon.invitationKey

        val myModelCon = wallet.findConnection { c -> c.id == pcon.id }
        myModelCon shouldBe pcon

        val myModelDid = wallet.findDid { d -> d.verkey == pcon.myVerkey }
        myModelDid shouldBe pcon.myDid
    }
}
