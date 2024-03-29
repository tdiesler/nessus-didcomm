/*-
 * #%L
 * Nessus DIDComm :: CLI
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
package org.nessus.didcomm.cli.protocol

import org.nessus.didcomm.cli.AbstractBaseCommand
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.MessageExchange.Companion.INVITATION_ATTACHMENT_KEY
import org.nessus.didcomm.service.OUT_OF_BAND_PROTOCOL_V2
import org.nessus.didcomm.service.TRUST_PING_PROTOCOL_V2
import org.nessus.didcomm.util.encodeJson
import picocli.CommandLine.Command
import picocli.CommandLine.Option
import java.net.URL

@Command(
    name = "invitation",
    description = ["Out-of-Band Invitation"],
    mixinStandardHelpOptions = true,
    subcommands = [
        CreateInvitation::class,
        ReceiveInvitation::class,
        InviteAndConnect::class,
    ]
)
class OutOfBandCommands

open class AbstractOutOfBandCommand: AbstractBaseCommand() {

    @Option(names = ["-v", "--verbose"], description = ["Verbose terminal output"])
    var verbose: Boolean = false

    fun echoCreateInvitation(name: String, invitation: Invitation) {
        val header = "$name created an Out-of-Band Invitation"
        if (verbose) {
            echo("${header}\n${invitation.encodeJson(true)}")
        } else {
            echo("${header}: ${invitation.shortString()}")
        }
    }

    fun echoReceiveInvitation(name: String, invitation: Invitation) {
        val header = "$name received an Out-of-Band Invitation"
        if (verbose) {
            echo("${header}\n${invitation.encodeJson(true)}")
        } else {
            echo("${header}: ${invitation.shortString()}")
        }
    }
}

@Command(name = "create", description = ["Create an Out-of-Band Invitation"], mixinStandardHelpOptions = true)
class CreateInvitation: AbstractOutOfBandCommand() {

    @Option(names = ["--inviter" ], description = ["Optional inviter alias"])
    var inviterAlias: String? = null

    @Option(names = ["--inviter-did" ], description = ["Optional inviter Did alias"])
    var inviterDidAlias: String? = null

    @Option(names = ["--method" ], description = ["Optional Did method"])
    var method: String? = null

    override fun call(): Int {
        val (inviter, inviterDid) = if (inviterDidAlias != null) {
            findWalletAndDidFromAlias(inviterAlias, inviterDidAlias)
        } else {
            val ctxWallet = getContextWallet(inviterAlias)
            val ctxDid = cliService.findContextDid(inviterAlias)
            Pair(ctxWallet, ctxDid)
        }
        checkNotNull(inviter) { "No inviter wallet" }
        checkWalletEndpoint(inviter)

        // Use given or created Dids
        val didMethod = method?.let { DidMethod.fromValue(method!!) } ?: DidMethod.PEER

        val mex = MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .createOutOfBandInvitation(inviter, inviterDid, didMethod)
            .getMessageExchange()

        val invitation = mex.getInvitation() as Invitation
        checkNotNull(inviter.getInvitation(invitation.id))
        cliService.putContextInvitation(invitation)
        echoCreateInvitation(inviter.alias, invitation)
        return 0
    }
}

@Command(name = "receive", description = ["Receive an Out-of-Band Invitation"], mixinStandardHelpOptions = true)
class ReceiveInvitation: AbstractOutOfBandCommand() {

    @Option(names = ["--inviter" ], description = ["Optional inviter alias"])
    var inviterAlias: String? = null

    @Option(names = ["--invitee" ], description = ["Optional invitee alias"])
    var inviteeAlias: String? = null

    @Option(names = ["--invitee-did" ], description = ["Optional invitee Did alias"])
    var inviteeDidAlias: String? = null

    @Option(names = ["--mediator" ], description = ["Optional inviter alias when mediator"])
    var mediatorAlias: String? = null

    @Option(names = ["-u", "--url" ], description = ["Optional invitation url"])
    var invitationUrl: String? = null

    override fun call(): Int {

        // Find Invitation
        val invitation = invitationUrl
            ?.let { Invitation.fromUrl(URL(invitationUrl!!)) }
            ?:let { cliService.findContextInvitation() }

        checkNotNull(invitation) { "No invitation" }

        // Find Invitee Wallet and Did
        val (invitee, inviteeDid) = if (inviteeDidAlias != null) {
            findWalletAndDidFromAlias(inviteeAlias, inviteeDidAlias)
        } else {
            Pair(getContextWallet(inviteeAlias), null)
        }
        checkNotNull(invitee) { "No invitee wallet" }

        val effectiveInviter = mediatorAlias ?: inviterAlias
        val isMediatorInvitation = mediatorAlias != null

        val mex = MessageExchange()
            .withAttachment(INVITATION_ATTACHMENT_KEY, invitation)
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .receiveOutOfBandInvitation(invitee, inviteeDid, effectiveInviter, fromMediator = isMediatorInvitation)
            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing()
            .awaitTrustPingResponse()
            .getMessageExchange()

        val pcon = mex.getConnection()
        check(invitee.findDid { d -> d.uri == pcon.myDid.uri } != null)

        cliService.putContextConnection(pcon)

        checkNotNull(invitee.getInvitation(invitation.id))
        echoReceiveInvitation(invitee.alias, invitation)
        cliService.putAttachment(INVITATION_ATTACHMENT_KEY, null)

        echo(pcon.shortString())
        if (verbose)
            echo(pcon.encodeJson(true))
        return 0
    }
}

@Command(name = "connect", description = ["Combine Invitation and Did Exchange"], mixinStandardHelpOptions = true)
class InviteAndConnect: AbstractOutOfBandCommand() {

    @Option(names = ["--inviter" ], description = ["Optional inviter alias"])
    var inviterAlias: String? = null

    @Option(names = ["--inviter-did" ], description = ["Optional inviter Did alias"])
    var inviterDidAlias: String? = null

    @Option(names = ["--invitee" ], description = ["Optional invitee alias"])
    var inviteeAlias: String? = null

    @Option(names = ["--invitee-did" ], description = ["Optional invitee Did alias"])
    var inviteeDidAlias: String? = null

    @Option(names = ["--method" ], description = ["Optional Did method"])
    var method: String? = null

    override fun call(): Int {

        // Find Invitee Wallet and Did
        val (inviter, inviterDidAux) = if (inviterDidAlias != null) {
            findWalletAndDidFromAlias(inviterAlias, inviterDidAlias)
        } else {
            Pair(getContextWallet(inviterAlias), null)
        }
        checkNotNull(inviter) { "No inviter wallet" }

        // Find Invitee Wallet and Did
        val (invitee, inviteeDidAux) = if (inviteeDidAlias != null) {
            findWalletAndDidFromAlias(inviteeAlias, inviteeDidAlias)
        } else {
            Pair(getContextWallet(inviteeAlias), null)
        }
        checkNotNull(invitee) { "No invitee wallet" }
        check(inviter != invitee) { "Inviter/Invitee cannot be the same: ${inviter.shortString()}" }

        // Check the wallet endpoints
        checkWalletEndpoint(inviter, invitee)

        // Use given or created Dids
        val didMethodAux = method?.let { DidMethod.fromValue(method!!) } ?: DidMethod.PEER
        var inviterDid: Did = inviterDidAux ?: inviter.createDid(didMethodAux)
        var inviteeDid: Did = inviteeDidAux ?: invitee.createDid(didMethodAux)

        val pcon = MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .createOutOfBandInvitation(inviter, inviterDid)
            .also {
                val invitation = it.getMessageExchange().getInvitation()
                echoCreateInvitation(inviter.alias, invitation!!)
            }
            .receiveOutOfBandInvitation(
                invitee,
                inviteeDid = inviteeDid,
                inviterAlias = inviter.alias)
            .also {
                val invitation = it.getMessageExchange().getInvitation()
                echoReceiveInvitation(invitee.alias, invitation!!)
            }
            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing()
            .awaitTrustPingResponse()
            .also {
                val pcon = it.getConnection()
                inviterDid = pcon.theirDid
                inviteeDid = pcon.myDid
            }
            .getConnection()

        check(pcon.myLabel == invitee.alias) { "Unexpected invitee label: ${pcon.myLabel}" }
        check(pcon.theirLabel == inviter.alias) { "Unexpected inviter label: ${pcon.theirLabel}" }

        cliService.putContextConnection(pcon)

        val inviterConnection = inviter.findConnection { c -> c.myDid == inviterDid && c.theirDid == inviteeDid }
        val inviteeConnection = invitee.findConnection { c -> c.myDid == inviteeDid && c.theirDid == inviterDid }
        checkNotNull(inviterConnection) { "No inviter connection" }
        checkNotNull(inviteeConnection) { "No invitee connection" }

        cliService.putAttachment(INVITATION_ATTACHMENT_KEY, null)
        echo(pcon.shortString())
        if (verbose)
            echo(pcon.encodeJson(true))
        return 0
    }
}

