package org.nessus.didcomm.cli.cmd

import org.nessus.didcomm.cli.cmd.AgentCommands.EndpointSpec
import org.nessus.didcomm.protocol.MessageExchange
import org.nessus.didcomm.service.RFC0023_DIDEXCHANGE
import org.nessus.didcomm.service.RFC0434_OUT_OF_BAND
import org.nessus.didcomm.wallet.AgentType
import org.nessus.didcomm.wallet.Wallet
import org.nessus.didcomm.wallet.toWalletModel
import picocli.CommandLine.Command
import picocli.CommandLine.Parameters
import java.net.URL
import java.util.concurrent.Callable

@Command(
    name = "rfc0023",
    description = ["RFC0023 Did Exchange"],
    subcommands = [
        RFC0023ConnectCommand::class,
    ]
)
class RFC0023Commands

@Command(name = "connect")
class RFC0023ConnectCommand: AbstractBaseCommand(), Callable<Int> {

    @Parameters(index = "0", description = ["The requester wallet name"])
    var requesterName: String? = null

    @Parameters(index = "1", description = ["The responder wallet name"])
    var responderName: String? = null

    override fun call(): Int {
        val requester = walletService.findByName(requesterName!!)
        val responder = walletService.findByName(responderName!!)
        checkNotNull(requester) { "No wallet for name: $requesterName" }
        checkNotNull(responder) { "No wallet for name: $responderName" }
        checkWalletEndpoint(requester)
        val connection = MessageExchange()
            .withProtocol(RFC0434_OUT_OF_BAND)
            .createOutOfBandInvitation(responder)
            .receiveOutOfBandInvitation(requester)
            .withProtocol(RFC0023_DIDEXCHANGE)
            .connect(requester)
        checkNotNull(requester.toWalletModel().getConnection(connection.id))
        println("${requester.name} now has a connection with ${responder.name} in state ${connection.state}")
        return 0
    }

    private fun checkWalletEndpoint(wallet: Wallet) {
        when (wallet.agentType) {
            AgentType.ACAPY -> {
                // Assume that AcaPy is running
            }
            AgentType.NESSUS -> {
                val url = URL(wallet.endpointUrl)
                val eps = EndpointSpec("", url.host, url.port)
                check(cliService.attachmentKeys.any {
                    val result = runCatching { EndpointSpec.valueOf(it.name) }
                    val keyHost = result.getOrNull()?.host
                    val keyPort = result.getOrNull()?.port
                    // [TODO] verify endpoint type/host
                    result.isSuccess && eps.port == keyPort
                }) { "No running endpoint for: ${wallet.endpointUrl}"}
            }
        }
    }
}
