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
import org.nessus.didcomm.json.model.RpcCommandService
import org.nessus.didcomm.json.model.WalletData
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.model.WalletRole

/**
 * It should be possible to drive Nessus DIDComm entirely through JSON-RPC
 */
class FaberAcmeThriftTest: AnnotationSpec() {
    private val log = KotlinLogging.logger {}

    private val rpcService get() = RpcCommandService.getService()

    @Test
    fun faberAcmeThrift() {
        val gov = createWallet("","Government", WalletRole.TRUSTEE)
        val faber = createWallet(gov.id,"Faber", WalletRole.ISSUER)
        val acme = createWallet(gov.id,"Acme", WalletRole.ISSUER)
        val thrift = createWallet(gov.id,"Thrift", WalletRole.ISSUER)
        val alice = createWallet(gov.id,"Alice", WalletRole.CLIENT)
        try {

        } finally {
            removeWallet(gov, alice)
            removeWallet(gov, thrift)
            removeWallet(gov, acme)
            removeWallet(gov, faber)
            removeWallet(gov, gov)
        }
    }

    private fun createWallet(caller: String, alias: String, role: WalletRole): Wallet {
        val path = "/wallet/create"
        val data = WalletData(alias = alias, walletRole = role)
        val res = rpcService.dispatchRpcCommand(caller, path, data.toJson())
        return res.shouldBeSuccess() as Wallet
    }

    private fun removeWallet(caller: Wallet, target: Wallet) {
        val path = "/wallet/remove"
        val data = WalletData(id = target.id)
        rpcService.dispatchRpcCommand(caller.id, path, data.toJson()).shouldBeSuccess()
    }
}
