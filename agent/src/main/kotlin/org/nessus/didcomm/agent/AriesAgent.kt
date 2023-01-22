package org.nessus.didcomm.agent

import org.hyperledger.aries.api.connection.ConnectionRecord
import org.nessus.didcomm.wallet.Wallet

class AriesAgent {

    companion object {

        fun adminClient(config: AgentConfiguration? = null) = AriesClientFactory.adminClient(config)
        fun walletClient(wallet: Wallet, config: AgentConfiguration) = AriesClientFactory.walletClient(wallet = wallet, config)

        fun awaitConnectionRecord(wallet: Wallet, predicate: (cr: ConnectionRecord) -> Boolean): ConnectionRecord? {
            var retries = 10
            val walletClient = wallet.walletClient() as AriesClient
            var maybeConnection = walletClient.connections().get().firstOrNull { predicate(it) }
            while (maybeConnection == null && (0 < retries--)) {
                Thread.sleep(500)
                maybeConnection = walletClient.connections().get().firstOrNull { predicate(it) }
            }
            return maybeConnection
        }
    }
}