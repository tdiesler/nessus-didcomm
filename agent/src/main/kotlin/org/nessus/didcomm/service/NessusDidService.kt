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
package org.nessus.didcomm.service

import id.walt.crypto.Key
import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.KeyId
import id.walt.crypto.convertRawKeyToMultiBase58Btc
import id.walt.crypto.decodeRawPubKeyBase64
import id.walt.crypto.getMulticodecKeyCode
import id.walt.crypto.newKeyId
import id.walt.model.ServiceEndpoint
import id.walt.servicematrix.ServiceProvider
import id.walt.services.CryptoProvider
import id.walt.services.keystore.KeyStoreService
import mu.KotlinLogging
import org.nessus.didcomm.crypto.LazySodiumService.convertEd25519toRaw
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidDocV2
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.util.decodeBase58
import org.nessus.didcomm.util.encodeBase58
import org.nessus.didcomm.util.encodeBase64
import java.security.KeyFactory
import java.security.KeyPair


val DEFAULT_KEY_ALGORITHM = KeyAlgorithm.EdDSA_Ed25519

typealias WaltIdDidService = id.walt.services.did.DidService
typealias WaltIdDidMethod = id.walt.model.DidMethod
typealias WaltIdDidDoc = id.walt.model.Did

class NessusDidService: AbstractBaseService() {
    override val implementation get() = serviceImplementation<NessusDidService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = NessusDidService()
        override fun getService() = implementation
    }

    private val modelService get() = ModelService.getService()
    private val cryptoService get() = NessusCryptoService.getService()
    private val keyStore get() = KeyStoreService.getService()

    fun createDid(method: DidMethod, keyAlias: String? = null): Did {
        
        val did = when(method) {
            DidMethod.KEY -> createDidKey(keyAlias)
            DidMethod.SOV -> createDidSov(keyAlias)
        }
        
        val didUrl = did.qualified
        val keyId = keyStore.load(didUrl).keyId

        if (method in listOf(DidMethod.KEY)) {
            val didDoc = WaltIdDidService.resolve(didUrl)
            didDoc.verificationMethod?.forEach { (id) ->
                keyStore.addAlias(keyId, id)
            }
            WaltIdDidService.storeDid(didUrl, didDoc.encodePretty())
        }

        return did
    }

    fun loadDid(did: String): Did {
        val didDoc = WaltIdDidService.load(did)
        val verificationMethod = didDoc.verificationMethod
            ?.firstOrNull { it.type.startsWith("Ed25519") }
        checkNotNull(verificationMethod) {"No suitable verification method: ${didDoc.encode()}"}
        val verkey = verificationMethod.publicKeyBase58
        checkNotNull(verkey) {"No verkey in: ${verificationMethod.id}"}
        val controller = verificationMethod.controller
        return Did.fromSpec(controller, verkey)
    }

    fun loadDidDocument(did: String): DidDocV2 {
        val didDoc = WaltIdDidService.load(did)
        if (didDoc.serviceEndpoint == null || didDoc.serviceEndpoint?.isEmpty() == true) {
            modelService.findWalletByDid(did)?.also {
                // Add the wallet's service endpoint when needed
                didDoc.serviceEndpoint = listOf(
                    ServiceEndpoint(
                        id = "${did}#didcomm-1",
                        type = "wallet-endpoint",
                        serviceEndpoint = listOf(it.endpointUrl)))
            }
        }
        return DidDocV2.fromWaltIdDidDoc(didDoc)
    }

    fun importDid(did: Did): KeyId {
        check(keyStore.getKeyId(did.verkey) == null) { "Did already registered: $did" }

        if (did.method in listOf(DidMethod.KEY))
            WaltIdDidService.importDid(did.qualified)

        val key = importDidKey(did)
        check(keyStore.getKeyId(did.verkey) != null)
        check(did.verkey == key.getPublicKeyBytes().encodeBase58())

        return key.keyId
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun createDidKey(keyAlias: String?): Did {
        val keyAlgorithm = DEFAULT_KEY_ALGORITHM
        val keyId = keyAlias?.let { KeyId(it) } ?: cryptoService.generateKey(keyAlgorithm)
        val key = keyStore.load(keyId.id)

        val pubkeyBytes = key.getPublicKey().convertEd25519toRaw()
        val identifier = convertRawKeyToMultiBase58Btc(pubkeyBytes, getMulticodecKeyCode(keyAlgorithm))
        val verkey = pubkeyBytes.encodeBase58()

        // Add verkey and did as alias
        val did = Did(identifier, DidMethod.KEY, keyAlgorithm, verkey)
        keyStore.addAlias(keyId, did.qualified)
        keyStore.addAlias(keyId, did.verkey)

        return did
    }

    private fun createDidSov(keyAlias: String?): Did {
        val keyAlgorithm = DEFAULT_KEY_ALGORITHM
        val keyId = keyAlias?.let { KeyId(it) } ?: cryptoService.generateKey(keyAlgorithm)
        val key = keyStore.load(keyId.id)

        val pubkeyBytes = key.getPublicKey().convertEd25519toRaw()
        val identifier =  pubkeyBytes.dropLast(16).toByteArray().encodeBase58()
        val verkey = pubkeyBytes.encodeBase58()

        // Add verkey and did as alias
        val did = Did(identifier, DidMethod.SOV, keyAlgorithm, verkey)
        keyStore.addAlias(keyId, did.qualified)
        keyStore.addAlias(keyId, did.verkey)

        return did
    }

    private fun importDidKey(did: Did): Key {

        check(did.algorithm == KeyAlgorithm.EdDSA_Ed25519) { "Unsupported key algorithm: $did" }
        val algorithm = did.algorithm
        val rawBytes = did.verkey.decodeBase58()
        val keyFactory = KeyFactory.getInstance("Ed25519")
        val publicKey = decodeRawPubKeyBase64(rawBytes.encodeBase64(), keyFactory)
        val key = Key(newKeyId(), algorithm, CryptoProvider.SUN, KeyPair(publicKey, null))

        keyStore.store(key)
        keyStore.addAlias(key.keyId, did.qualified)
        keyStore.addAlias(key.keyId, did.verkey)
        return key
    }
}
