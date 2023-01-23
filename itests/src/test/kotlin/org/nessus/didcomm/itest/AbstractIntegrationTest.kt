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
package org.nessus.didcomm.itest

import id.walt.servicematrix.ServiceMatrix
import id.walt.services.crypto.CryptoService
import id.walt.services.keystore.KeyStoreService
import mu.KotlinLogging
import org.junit.jupiter.api.BeforeAll
import org.nessus.didcomm.crypto.NessusCryptoService
import org.nessus.didcomm.protocol.Protocol
import org.nessus.didcomm.service.CamelEndpointService
import org.nessus.didcomm.service.DataModelService
import org.nessus.didcomm.service.DidDocumentService
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.service.HttpService
import org.nessus.didcomm.service.MessageDispatchService
import org.nessus.didcomm.service.ProtocolKey
import org.nessus.didcomm.service.ProtocolService
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.util.encodeHex
import org.nessus.didcomm.wallet.Wallet

val ACAPY_OPTIONS_01 = mapOf(
    "ACAPY_HOSTNAME" to System.getenv("EXTERNAL_IP"),
    "ACAPY_ADMIN_PORT" to "8031",
    "ACAPY_USER_PORT" to "8030",
)

val ACAPY_OPTIONS_02 = mapOf(
    "ACAPY_HOSTNAME" to System.getenv("EXTERNAL_IP"),
    "ACAPY_ADMIN_PORT" to "8041",
    "ACAPY_USER_PORT" to "8040",
)

val NESSUS_OPTIONS_01 = mapOf(
    "NESSUS_HOSTNAME" to System.getenv("EXTERNAL_IP"),
    "NESSUS_USER_PORT" to "8130",
)

val NESSUS_OPTIONS_02 = mapOf(
    "NESSUS_HOSTNAME" to System.getenv("EXTERNAL_IP"),
    "NESSUS_USER_PORT" to "8140",
)

object Government {
    val name = "Government"
    val seed = "000000000000000000000000Trustee1"
    val seedHex = seed.toByteArray().encodeHex()
    val verkey = "GJ1SzoWzavQYfNL9XkaJdrQejfztN4XqdsiV4ct3LXKL"
    val didkey = "did:key:z6MkukGVb3mRvTu1msArDKY9UwxeZFGjmwnCKtdQttr4Fk6i"
}
object Faber {
    val name = "Faber"
    val seed = "00000000000000000000000Endorser1"
    val seedHex = seed.toByteArray().encodeHex()
    val verkey = "CcokUqV7WkojBLxYm7gxRzsWk3q4SE8eVMmEXoYjyvKw"
    val didkey = "did:key:z6Mkr54o55jYrJJCHqoFSgeoH6RWZd6ur7P1BNgAN5Wku97K"
}
object Alice {
    val name = "Alice"
    val seed = "00000000000000000000000000Alice1"
    val seedHex = seed.toByteArray().encodeHex()
    val verkey = "ESqH2YuYRRXMMfg5qQh1A23nzBaUvAMCEXLtBr2uDHbY"
    val didkey = "did:key:z6Mksu6Kco9yky1pUAWnWyer17bnokrLL3bYvYFp27zv8WNv"
}

const val RESOURCES_PATH: String = "src/test/resources"

abstract class AbstractIntegrationTest {

    val log = KotlinLogging.logger {}

    companion object {
        @BeforeAll
        @JvmStatic
        internal fun beforeAll() {
            ServiceMatrix("${RESOURCES_PATH}/service-matrix.properties")
        }
    }

    val cryptoService get() = CryptoService.getService().implementation as NessusCryptoService
    val didService get() = DidService.getService()
    val diddocService = DidDocumentService.getService()
    val dispatchService = MessageDispatchService.getService()
    val endpointService get() = CamelEndpointService.getService()
    val httpService get() = HttpService.getService()
    val keyStore get() = KeyStoreService.getService()
    val modelService get() = DataModelService.getService()
    val protocolService get() = ProtocolService.getService()
    val walletService get() = WalletService.getService()

    val httpClient get() = httpService.httpClient()

    fun getWalletByAlias(alias: String): Wallet? {
        return walletService.findByName(alias)
    }

    fun <P: Protocol> getProtocol(key: ProtocolKey<P>): P {
        return protocolService.getProtocol(key)
    }

    fun removeWallet(alias: String) {
        walletService.findByName(alias)?.run {
            walletService.removeWallet(this.id)
        }
    }
}
