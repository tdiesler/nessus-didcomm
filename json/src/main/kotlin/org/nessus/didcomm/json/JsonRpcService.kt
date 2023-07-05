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
package org.nessus.didcomm.json

import mu.KotlinLogging
import org.nessus.didcomm.service.ObjectService
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.util.AttachmentSupport
import kotlin.reflect.KClass

open class RpcContext(headers: Map<String, String> = emptyMap()): AttachmentSupport() {

    init {
        headers.entries.forEach { (k, v) -> putAttachment(k, String::class, v) }
    }

    fun <T: Any> getAttachment(name: String, type: KClass<T>): T? {
        return getAttachment(AttachmentKey(name, type))
    }

    fun <T: Any> putAttachment(name: String, type: KClass<T>, obj: T?): T? {
        return putAttachment(AttachmentKey(name, type), obj)
    }

    class Builder {
        private val content = mutableMapOf<String, String>()
        fun attach(key: String, value: String) = also { content[key] = value }
        fun build() = RpcContext(content)
    }
}

object JsonRpcService: ObjectService<JsonRpcService>() {
    private val log = KotlinLogging.logger {}

    override fun getService() = apply { }

    fun dispatchRpcCommand(path: String, payload: String): Result<Any?> {
        val obj: Any? = when (path) {
            "/connection/create" -> ConnectionRpcHandler.createConnection(payload)
            "/did/create" -> DidRpcHandler.createDid(payload)
            "/did/list" -> DidRpcHandler.listDids(payload)
            "/invitation/create" -> InvitationRpcHandler.createInvitation(payload)
            "/invitation/receive" -> InvitationRpcHandler.receiveInvitation(payload)
            "/vc/issue" -> VCRpcHandler.issueCredential(payload)
            "/wallet/create" -> WalletRpcHandler.createWallet(payload)
            "/wallet/find" -> WalletRpcHandler.findWallet(payload)
            "/wallet/list" -> WalletRpcHandler.listWallets(payload)
            "/wallet/remove" -> WalletRpcHandler.removeWallet(payload)
            else -> throw IllegalStateException("Unsupported command path: $path")
        }
        return Result.success(obj)
    }
}
