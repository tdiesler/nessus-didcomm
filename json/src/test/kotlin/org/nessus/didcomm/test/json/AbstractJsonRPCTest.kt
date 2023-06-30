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
import org.nessus.didcomm.json.model.ConnectionData
import org.nessus.didcomm.json.model.DidData
import org.nessus.didcomm.json.model.InvitationData
import org.nessus.didcomm.json.model.WalletData
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.Invitation
import org.nessus.didcomm.model.NessusWalletPlugin
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.model.WalletRole
import org.nessus.didcomm.service.EndpointService
import org.nessus.didcomm.service.MessageReceiver
import org.nessus.didcomm.service.ModelService
import org.nessus.didcomm.service.ServiceMatrixLoader

/**
 * It should be possible to drive Nessus DIDComm entirely through JSON-RPC
 */
@Suppress("MemberVisibilityCanBePrivate")
abstract class AbstractJsonRPCTest : AnnotationSpec() {
    val log = KotlinLogging.logger {}

    val rpcService get() = RpcCommandService.getService()
    val modelService get() = ModelService.getService()
    val endpointService get() = EndpointService.getService()

    val endpointHandle = ThreadLocal<AutoCloseable>()

    @BeforeAll
    fun beforeAll() {
        val matrixProperties = "src/test/resources/config/service-matrix.properties"
        ServiceMatrixLoader.loadServiceDefinitions(matrixProperties)
    }

    @AfterAll
    fun afterAll() {
        stopNessusEndpoint()
    }

    // region endpoint
    fun startNessusEndpoint(listener: MessageReceiver? = null): AutoCloseable {
        val endpointUrl = NessusWalletPlugin.getEndpointUrl()
        val handle = endpointService.startEndpoint(endpointUrl, listener)
        endpointHandle.set(handle)
        return handle
    }

    fun stopNessusEndpoint(handle: AutoCloseable? = null) {
        val auxhdl = handle ?: endpointHandle.get()
        auxhdl?.also { endpointService.stopEndpoint(auxhdl) }
    }
    // endregion

    // region connection
    fun createConnection(data: ConnectionData): Connection {
        val path = "/connection/create"
        val res = rpcService.dispatchRpcCommand(path, data.toJson())
        return res.shouldBeSuccess() as Connection
    }
    // endregion

    // region did
    fun createDid(owner: Wallet, method: DidMethod? = null, options: Map<String, Any> = emptyMap()): Did {
        return createDid(DidData(owner.id, method = method, options = options))
    }

    fun createDid(data: DidData): Did {
        val path = "/did/create"
        val res = rpcService.dispatchRpcCommand(path, data.toJson())
        return res.shouldBeSuccess() as Did
    }
    // endregion

    // region invitation
    fun createInvitation(data: InvitationData): Invitation {
        val path = "/invitation/create"
        val res = rpcService.dispatchRpcCommand(path, data.toJson())
        return res.shouldBeSuccess() as Invitation
    }

    fun receiveInvitation(data: InvitationData): Connection {
        val path = "/invitation/receive"
        val res = rpcService.dispatchRpcCommand(path, data.toJson())
        return res.shouldBeSuccess() as Connection
    }
    // endregion

    // region wallet
    fun createWallet(alias: String, walletRole: WalletRole? = null): Wallet {
        return createWallet(WalletData(alias = alias, walletRole = walletRole))
    }

    fun createWallet(data: WalletData): Wallet {
        val path = "/wallet/create"
        val res = rpcService.dispatchRpcCommand(path, data.toJson())
        return res.shouldBeSuccess() as Wallet
    }

    fun removeWallets(vararg wallets: Wallet) {
        wallets.forEach { removeWallet(it) }
    }

    fun removeWallet(wallet: Wallet) {
        val path = "/wallet/remove"
        val data = WalletData(id = wallet.id)
        rpcService.dispatchRpcCommand(path, data.toJson()).shouldBeSuccess()
    }
    // endregion
}
