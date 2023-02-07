/*-
 * #%L
 * Nessus DIDComm :: Agent
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
package org.nessus.didcomm.agent

import org.hyperledger.aries.api.connection.ConnectionRecord
import org.nessus.didcomm.wallet.AcapyWallet

class AriesAgent {

    companion object {

        fun adminClient(config: AgentConfiguration? = null) = AriesClientFactory.adminClient(config)
        fun walletClient(wallet: AcapyWallet, config: AgentConfiguration) = AriesClientFactory.walletClient(wallet = wallet, config)

        fun awaitConnectionRecord(wallet: AcapyWallet, predicate: (cr: ConnectionRecord) -> Boolean): ConnectionRecord? {
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
