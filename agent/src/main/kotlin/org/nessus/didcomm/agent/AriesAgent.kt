package org.nessus.didcomm.agent

import org.hyperledger.aries.api.connection.ConnectionRecord
import org.nessus.didcomm.wallet.Wallet
import org.slf4j.event.Level

class AriesAgent {

    companion object {

        private val interceptorLogLevel = Level.INFO
        fun adminClient(config: AgentConfiguration? = null) = AriesClientFactory.adminClient(config, level = interceptorLogLevel)
        fun walletClient(wallet: Wallet, config: AgentConfiguration) = AriesClientFactory.walletClient(wallet = wallet, config, level = interceptorLogLevel)

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