package org.nessus.didcomm.agent

import org.nessus.didcomm.wallet.NessusWallet
import org.slf4j.event.Level

class AriesAgent {

    companion object {
        private val implementation = AriesAgent()
        fun getService() = implementation

        private val interceptorLogLevel = Level.DEBUG
        fun adminClient() = AriesClientFactory.adminClient(level = interceptorLogLevel)
        fun walletClient(wallet: NessusWallet) =
            AriesClientFactory.walletClient(wallet = wallet, level = interceptorLogLevel)
    }
}