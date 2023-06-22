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
package org.nessus.didcomm.json.model

import mu.KotlinLogging
import org.nessus.didcomm.service.ObjectService
import org.nessus.didcomm.service.WalletService

object RpcCommandService: ObjectService<RpcCommandService>() {
    private val log = KotlinLogging.logger {}

    override fun getService() = apply { }

    private val walletService get() = WalletService.getService()

    fun dispatchRpcCommand(callerId: String, path: String, payload: String): Result<Any?> {
        return dispatchRpcCommand(callerId, emptyMap(), path, payload)
    }

    fun dispatchRpcCommand(callerId: String, headers: Map<String, String>, path: String, payload: String): Result<Any?> {
        val caller = walletService.findWallet(callerId)?.name ?: "Anonymous"
        log.info { "Json-RPC $caller: $path $payload" }
        val obj: Any? = when (path) {
            "/wallet/create" -> WalletCommandHandler.createWallet(callerId, payload)
            "/wallet/find" -> WalletCommandHandler.findWallet(callerId, payload)
            "/wallet/list" -> WalletCommandHandler.listWallets(callerId, payload)
            "/wallet/remove" -> WalletCommandHandler.removeWallet(callerId, payload)
            else -> throw IllegalStateException("Unsupported command path: $path")
        }
        return Result.success(obj)
    }
}
