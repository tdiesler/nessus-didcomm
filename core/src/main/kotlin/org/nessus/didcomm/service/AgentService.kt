package org.nessus.didcomm.service

import org.didcommx.didcomm.message.Message
import org.nessus.didcomm.wallet.NessusWallet

/**
 * An Agent can create, send, receive DIDComMessages
 */
interface AgentService : Service {

    companion object {
        val type: Class<AgentService> = AgentService::class.java
    }

    override val type: Class<AgentService>
        get() = Companion.type

    fun createMessage(wallet: NessusWallet, type: String, body: Map<String, Any> = mapOf()) : Message
}
