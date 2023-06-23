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
package org.nessus.didcomm.test.json

import io.kotest.core.spec.style.AnnotationSpec
import io.kotest.matchers.result.shouldBeSuccess
import mu.KotlinLogging
import org.nessus.didcomm.json.RpcCommandService
import org.nessus.didcomm.json.model.DidData
import org.nessus.didcomm.json.model.WalletData
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.model.WalletRole
import org.nessus.didcomm.service.ServiceMatrixLoader

/**
 * It should be possible to drive Nessus DIDComm entirely through JSON-RPC
 */
abstract class AbstractJsonRPCTest : AnnotationSpec() {
    val log = KotlinLogging.logger {}

    val rpcService get() = RpcCommandService.getService()

    @BeforeAll
    fun beforeAll() {
        val matrixProperties = "src/test/resources/config/service-matrix.properties"
        ServiceMatrixLoader.loadServiceDefinitions(matrixProperties)
    }

    fun createDid(caller: String, method: DidMethod, options: Map<String, Any> = emptyMap()): Did {
        val path = "/did/create"
        val data = DidData(method, options = options)
        val res = rpcService.dispatchRpcCommand(caller, path, data.toJson())
        return res.shouldBeSuccess() as Did
    }

    fun createWallet(caller: String, alias: String, role: WalletRole): Wallet {
        val path = "/wallet/create"
        val data = WalletData(alias = alias, walletRole = role)
        val res = rpcService.dispatchRpcCommand(caller, path, data.toJson())
        return res.shouldBeSuccess() as Wallet
    }

    fun removeWallet(wallet: Wallet) {
        val path = "/wallet/remove"
        val data = WalletData(id = wallet.id)
        rpcService.dispatchRpcCommand(wallet.id, path, data.toJson()).shouldBeSuccess()
    }
}
