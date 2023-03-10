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
package org.nessus.didcomm.test

import id.walt.credentials.w3c.templates.VcTemplateService
import id.walt.services.keystore.KeyStoreService
import io.kotest.core.spec.style.AnnotationSpec
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.protocol.MessageListener
import org.nessus.didcomm.service.DidCommService
import org.nessus.didcomm.service.DidDocumentV1Service
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.service.EndpointService
import org.nessus.didcomm.service.MessageDispatchService
import org.nessus.didcomm.service.ModelService
import org.nessus.didcomm.service.NessusCryptoService
import org.nessus.didcomm.service.NessusPolicyRegistryService
import org.nessus.didcomm.service.SecretResolverService
import org.nessus.didcomm.service.ServiceMatrixLoader
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.util.encodeHex
import org.nessus.didcomm.w3c.NessusAuditorService
import org.nessus.didcomm.w3c.NessusCustodianService
import org.nessus.didcomm.w3c.NessusSignatoryService
import org.nessus.didcomm.wallet.NessusWalletPlugin.Companion.getNessusEndpointUrl

val ACAPY_OPTIONS_01 = mapOf(
    "ACAPY_HOSTNAME" to System.getenv("ACAPY_HOSTNAME"),
    "ACAPY_ADMIN_PORT" to "8031",
    "ACAPY_USER_PORT" to "8030",
)

val ACAPY_OPTIONS_02 = mapOf(
    "ACAPY_HOSTNAME" to System.getenv("ACAPY_HOSTNAME"),
    "ACAPY_ADMIN_PORT" to "8041",
    "ACAPY_USER_PORT" to "8040",
)

val NESSUS_OPTIONS_01 = mapOf(
    "NESSUS_HOSTNAME" to System.getenv("NESSUS_HOSTNAME"),
    "NESSUS_USER_PORT" to "8130",
)

val NESSUS_OPTIONS_02 = mapOf(
    "NESSUS_HOSTNAME" to System.getenv("NESSUS_HOSTNAME"),
    "NESSUS_USER_PORT" to "8140",
)

object Government {
    val name = "Government"
    val seed = "000000000000000000000000Trustee1"
    val seedHex = seed.toByteArray().encodeHex()
    val verkey = "GJ1SzoWzavQYfNL9XkaJdrQejfztN4XqdsiV4ct3LXKL"
    val didkey = "did:key:z6MkukGVb3mRvTu1msArDKY9UwxeZFGjmwnCKtdQttr4Fk6i"
    val didsov = "did:sov:V4SGRU86Z58d6TV7PBUe6f"
}
object Faber {
    val name = "Faber"
    val seed = "00000000000000000000000Endorser1"
    val seedHex = seed.toByteArray().encodeHex()
    val verkey = "CcokUqV7WkojBLxYm7gxRzsWk3q4SE8eVMmEXoYjyvKw"
    val didkey = "did:key:z6Mkr54o55jYrJJCHqoFSgeoH6RWZd6ur7P1BNgAN5Wku97K"
    val didsov = "did:sov:NKGKtcNwssToP5f7uhsEs4"
}
object Alice {
    val name = "Alice"
    val seed = "00000000000000000000000000Alice1"
    val seedHex = seed.toByteArray().encodeHex()
    val verkey = "ESqH2YuYRRXMMfg5qQh1A23nzBaUvAMCEXLtBr2uDHbY"
    val didkey = "did:key:z6Mksu6Kco9yky1pUAWnWyer17bnokrLL3bYvYFp27zv8WNv"
    val didpeer0 = "did:peer:0z6Mksu6Kco9yky1pUAWnWyer17bnokrLL3bYvYFp27zv8WNv"
    val didsov = "did:sov:RfoA7oboFMiFuJPEtPdvKP"
}
object Acme {
    val name = "Acme"
    val seed = "000000000000000000000000000Acme1"
    val seedHex = seed.toByteArray().encodeHex()
    val verkey = "4uGbbt1jJf69tjCfTiimoEtWsdCSuKndfEfFVYaw5ou4"
    val didkey = "did:key:z6MkiMXeC8GAeCad1E3N9HgceLSWhCUJKD2zMFaBKpYx12gS"
    val didpeer = "did:peer:0z6MkiMXeC8GAeCad1E3N9HgceLSWhCUJKD2zMFaBKpYx12gS"
    val didsov = "did:sov:8A9VYDjAVEqWrsfjLA3VDc"
}

@Suppress("MemberVisibilityCanBePrivate")
abstract class AbstractAgentTest: AnnotationSpec() {

    @BeforeAll
    fun beforeAll() {
        val matrixProperties = "src/test/resources/config/service-matrix.properties"
        ServiceMatrixLoader.loadServiceDefinitions(matrixProperties)
    }

    val auditor = NessusAuditorService.getService()
    val cryptoService get() = NessusCryptoService.getService()
    val custodian = NessusCustodianService.getService()
    val didComm get() = DidCommService.getService()
    val diddocV1Service get() = DidDocumentV1Service.getService()
    val didService get() = DidService.getService()
    val dispatchService = MessageDispatchService.getService()
    val endpointService get() = EndpointService.getService()
    val keyStore get() = KeyStoreService.getService()
    val modelService get() = ModelService.getService()
    val policyService get() = NessusPolicyRegistryService.getService()
    val secretResolver get() = SecretResolverService.getService()
    val signatory = NessusSignatoryService.getService()
    val templateService get() = VcTemplateService.getService()
    val walletService get() = WalletService.getService()

    fun readResource(path: String): String {
        val url = javaClass.getResource(path)
        checkNotNull(url) { "No resource: $path" }
        return url.readText()
    }

    fun startNessusEndpoint(options: Map<String, Any>, listener: MessageListener? = null): AutoCloseable {
        val endpointUrl = getNessusEndpointUrl(options)
        return endpointService.startEndpoint(endpointUrl, listener)
    }

    fun removeWallet(wallet: Wallet) {
        walletService.removeWallet(wallet.id)
    }
}
