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

import org.nessus.didcomm.model.WalletRole

/**
 * It should be possible to drive Nessus DIDComm entirely through JSON-RPC
 */
class FaberAcmeThriftTest: AbstractJsonRPCTest() {

    @Test
    fun faberAcmeThrift() {
        val gov = createWallet("","Government", WalletRole.TRUSTEE)
        val faber = createWallet(gov.id,"Faber", WalletRole.ISSUER)
        val acme = createWallet(gov.id,"Acme", WalletRole.ISSUER)
        val thrift = createWallet(gov.id,"Thrift", WalletRole.ISSUER)
        val alice = createWallet(gov.id,"Alice", WalletRole.CLIENT)
        try {


        } finally {
            removeWallet(alice)
            removeWallet(thrift)
            removeWallet(acme)
            removeWallet(faber)
            removeWallet(gov)
        }
    }
}
