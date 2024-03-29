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
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.nessus.didcomm.model.Connection
import org.nessus.didcomm.model.ConnectionState
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.NessusWalletPlugin
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.service.DidCommService
import org.nessus.didcomm.service.DidService
import org.nessus.didcomm.service.EndpointService
import org.nessus.didcomm.service.ISSUE_CREDENTIAL_PROTOCOL_V3
import org.nessus.didcomm.service.MessageDispatchService
import org.nessus.didcomm.service.MessageReceiver
import org.nessus.didcomm.service.MessageReceiverService
import org.nessus.didcomm.service.ModelService
import org.nessus.didcomm.service.NessusAuditorService
import org.nessus.didcomm.service.NessusCryptoService
import org.nessus.didcomm.service.NessusCustodianService
import org.nessus.didcomm.service.NessusPolicyRegistryService
import org.nessus.didcomm.service.NessusSignatoryService
import org.nessus.didcomm.service.OUT_OF_BAND_PROTOCOL_V2
import org.nessus.didcomm.service.PropertiesService
import org.nessus.didcomm.service.RevocationService
import org.nessus.didcomm.service.SecretResolverService
import org.nessus.didcomm.service.ServiceMatrixLoader
import org.nessus.didcomm.service.TRUST_PING_PROTOCOL_V2
import org.nessus.didcomm.service.WalletService
import org.nessus.didcomm.util.encodeHex

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
object Acme {
    val name = "Acme"
    val seed = "000000000000000000000000000Acme1"
    val seedHex = seed.toByteArray().encodeHex()
    val verkey = "4uGbbt1jJf69tjCfTiimoEtWsdCSuKndfEfFVYaw5ou4"
    val didkey = "did:key:z6MkiMXeC8GAeCad1E3N9HgceLSWhCUJKD2zMFaBKpYx12gS"
    val didpeer = "did:peer:0z6MkiMXeC8GAeCad1E3N9HgceLSWhCUJKD2zMFaBKpYx12gS"
    val didsov = "did:sov:8A9VYDjAVEqWrsfjLA3VDc"
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

@Suppress("MemberVisibilityCanBePrivate")
abstract class AbstractAgentTest: AnnotationSpec() {
    val log = KotlinLogging.logger {this.javaClass}

    @BeforeAll
    open fun beforeAll() {
        val matrixProperties = "src/test/resources/config/service-matrix.properties"
        ServiceMatrixLoader.loadServiceDefinitions(matrixProperties)
    }

    @AfterAll
    open fun afterAll() {
        stopNessusEndpoint()
    }

    val auditor get() = NessusAuditorService.getService()
    val cryptoService get() = NessusCryptoService.getService()
    val custodian get() = NessusCustodianService.getService()
    val didComm get() = DidCommService.getService()
    val didService get() = DidService.getService()
    val dispatchService get() = MessageDispatchService.getService()
    val endpointService get() = EndpointService.getService()
    val keyStore get() = KeyStoreService.getService()
    val modelService get() = ModelService.getService()
    val policyService get() = NessusPolicyRegistryService.getService()
    val receiverService get() = MessageReceiverService.getService()
    val revocationService get() = RevocationService.getService()
    val secretResolver get() = SecretResolverService.getService()
    val signatory get() = NessusSignatoryService.getService()
    val templateService get() = VcTemplateService.getService()
    val walletService get() = WalletService.getService()

    val endpointHandle = ThreadLocal<AutoCloseable>()

    fun readResource(path: String): String {
        val url = javaClass.getResource(path)
        checkNotNull(url) { "No resource: $path" }
        return url.readText()
    }

    fun startNessusEndpoint(listener: MessageReceiver? = null): AutoCloseable {
        val endpointUrl = NessusWalletPlugin.getEndpointUrl()
        val handle = endpointService.startEndpoint(endpointUrl, listener)
        endpointHandle.set(handle)
        return handle
    }

    fun stopNessusEndpoint(handle: AutoCloseable? = null) {
        val optHandle = handle ?: endpointHandle.get()
        optHandle?.also { endpointService.stopEndpoint(it) }
    }

    fun peerConnect(inviter: Wallet, invitee: Wallet, reverse: Boolean = false): Connection {
        val inviteeCon = MessageExchange()
            .withProtocol(OUT_OF_BAND_PROTOCOL_V2)
            .createOutOfBandInvitation(inviter)
            .receiveOutOfBandInvitation(invitee, inviterAlias = inviter.alias)
            .withProperty(PropertiesService.PROTOCOL_TRUST_PING_ROTATE_DID, false)
            .withProtocol(TRUST_PING_PROTOCOL_V2)
            .sendTrustPing()
            .awaitTrustPingResponse()
            .getConnection()

        inviteeCon.state shouldBe ConnectionState.ACTIVE
        if (reverse)
            return inviteeCon

        check(inviteeCon.theirLabel == inviter.alias)
        val inviterDid = inviteeCon.theirDid
        val inviteeDid = inviteeCon.myDid
        val inviterCon = inviter.findConnection { it.myDid == inviterDid && it.theirDid == inviteeDid }
        return checkNotNull(inviterCon) { "No ${inviter.alias}_${invitee.alias} connection" }
    }

    fun issueCredential(issuer: Wallet, holderDid: Did, template: String, subjectData: Map<String, Any?>) {
        val pcon = issuer.findConnection { it.theirDid == holderDid }
        checkNotNull(pcon) { "Issuer '${issuer.alias}' has no connection with: $holderDid" }
        MessageExchange()
            .withConnection(pcon)
            .withProtocol(ISSUE_CREDENTIAL_PROTOCOL_V3)
            .sendCredentialOffer(
                issuer = issuer,
                holderDid = holderDid,
                template = template,
                subjectData = subjectData
            )
            .awaitCredentialRequest(issuer, holderDid)
            .awaitCredentialAck(issuer, holderDid)
    }

    fun walletByName(name: String): Wallet {
        return walletService.findWallet(name) as Wallet
    }

    fun removeWallets(vararg wallets: Wallet) {
        if (wallets.isEmpty()) {
            walletService.wallets.forEach { removeWallet(it) }
        } else
            wallets.forEach { removeWallet(it) }
    }

    fun removeWallet(wallet: Wallet?) {
        wallet?.also { walletService.removeWallet(it.id) }
    }
}
