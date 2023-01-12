package org.nessus.didcomm.agent

import org.hyperledger.aries.api.connection.ConnectionRecord
import org.nessus.didcomm.wallet.Wallet
import org.slf4j.event.Level

class AriesAgent {

    companion object {
        private val implementation = AriesAgent()
        fun getService() = implementation

        private val interceptorLogLevel = Level.INFO
        fun adminClient() = AriesClientFactory.adminClient(level = interceptorLogLevel)
        fun walletClient(wallet: Wallet) = AriesClientFactory.walletClient(wallet = wallet, level = interceptorLogLevel)

        fun awaitConnectionRecord(wallet: Wallet, predicate: (cr: ConnectionRecord) -> Boolean): ConnectionRecord? {
            var retries = 10
            val walletClient = walletClient(wallet)
            var maybeConnection = walletClient.connections().get().firstOrNull { predicate(it) }
            while (maybeConnection == null && (0 < retries--)) {
                Thread.sleep(500)
                maybeConnection = walletClient.connections().get().firstOrNull { predicate(it) }
            }
            return maybeConnection
        }
    }
}