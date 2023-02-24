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
@file:Suppress("unused")

package org.nessus.didcomm.service

import id.walt.crypto.Key
import id.walt.crypto.KeyFormat
import id.walt.crypto.KeyId
import id.walt.crypto.LdVerificationKeyType
import id.walt.crypto.buildKey
import id.walt.crypto.convertMultiBase58BtcToRawKey
import id.walt.crypto.convertPublicKeyEd25519ToCurve25519
import id.walt.crypto.convertRawKeyToMultiBase58Btc
import id.walt.crypto.convertX25519PublicKeyToMultiBase58Btc
import id.walt.crypto.decodeBase58
import id.walt.crypto.encodeBase58
import id.walt.crypto.getMulticodecKeyCode
import id.walt.crypto.newKeyId
import id.walt.model.DID_CONTEXT_URL
import id.walt.model.DidUrl
import id.walt.model.ServiceEndpoint
import id.walt.model.VerificationMethod
import id.walt.services.context.ContextManager
import id.walt.services.hkvstore.HKVKey
import id.walt.services.keystore.KeyStoreService
import mu.KotlinLogging
import org.nessus.didcomm.crypto.LazySodiumService.convertEd25519toRaw
import org.nessus.didcomm.did.DEFAULT_KEY_ALGORITHM
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.Did.Companion.extractDidMethod
import org.nessus.didcomm.did.Did.Companion.fromWaltIdDid
import org.nessus.didcomm.did.DidDocV2
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.did.KeyAlgorithm
import org.nessus.didcomm.util.encodeBase64


typealias WaltIdDidService = id.walt.services.did.DidService
typealias WaltIdDidMethod = id.walt.model.DidMethod
typealias WaltIdDid = id.walt.model.Did

object NessusDidService: ObjectService<NessusDidService>() {
    val log = KotlinLogging.logger {}

    override fun getService() = apply { }

    private val modelService get() = ModelService.getService()
    private val cryptoService get() = NessusCryptoService.getService()
    private val keyStore get() = KeyStoreService.getService()

    fun createDid(method: DidMethod, keyAlias: String? = null): Did {
        val did = when(method) {
            DidMethod.KEY -> DidKeyPlugin.createDid(keyAlias)
            DidMethod.PEER -> DidPeerPlugin.createDid(keyAlias)
            DidMethod.SOV -> DidSovPlugin.createDid(keyAlias)
        }
        return did
    }

    fun removeDid(did: Did) {
        try {
            when(did.method) {
                DidMethod.KEY -> DidKeyPlugin.removeDid(did)
                DidMethod.PEER -> DidPeerPlugin.removeDid(did)
                DidMethod.SOV -> DidSovPlugin.removeDid(did)
            }
        } catch (e: Exception) {
            log.error(e) { "Cannot remove did: ${did.uri}" }
        }
    }

    fun hasDid(did: String): Boolean {
        return try {
            WaltIdDidService.load(did)
            true
        } catch (e: RuntimeException) {
            false
        }
    }

    fun loadDid(uri: String): Did {
        val did = when(extractDidMethod(uri)) {
            DidMethod.KEY -> DidKeyPlugin.loadDid(uri)
            DidMethod.PEER -> DidPeerPlugin.loadDid(uri)
            DidMethod.SOV -> DidSovPlugin.loadDid(uri)
        }
        return did
    }

    fun loadDidDocument(uri: String): DidDocV2 {
        val didDoc = when(extractDidMethod(uri)) {
            DidMethod.KEY -> DidKeyPlugin.loadDidDoc(uri)
            DidMethod.PEER -> DidPeerPlugin.loadDidDoc(uri)
            DidMethod.SOV -> DidSovPlugin.loadDidDoc(uri)
        }
        addWalletServiceEndpoint(didDoc)
        return DidDocV2.fromWaltIdDid(didDoc)
    }

    fun resolveDid(uri: String): Did? {
        return when(extractDidMethod(uri)) {
            DidMethod.KEY -> DidKeyPlugin.resolveDid(uri)
            DidMethod.PEER -> DidPeerPlugin.resolveDid(uri)
            DidMethod.SOV -> DidSovPlugin.resolveDid(uri)
        }
    }

    fun resolveDidDocument(uri: String): DidDocV2? {
        return when(extractDidMethod(uri)) {
            DidMethod.KEY -> DidKeyPlugin.resolveDidDoc(uri)
            DidMethod.PEER -> DidPeerPlugin.resolveDidDoc(uri)
            DidMethod.SOV -> DidSovPlugin.resolveDidDoc(uri)
        }?.let {
            addWalletServiceEndpoint(it)
            DidDocV2.fromWaltIdDid(it)
        }
    }

    fun importDid(did: Did): KeyId {
        return when(did.method) {
            DidMethod.KEY -> DidKeyPlugin.importDid(did)
            DidMethod.PEER -> DidPeerPlugin.importDid(did)
            DidMethod.SOV -> DidSovPlugin.importDid(did)
        }
    }

    // Private ---------------------------------------------------------------------------------------------------------

    private fun addWalletServiceEndpoint(did: WaltIdDid) {
        if (did.serviceEndpoint == null || did.serviceEndpoint?.isEmpty() == true) {
            modelService.findWalletByDid(did.id)?.also {
                did.serviceEndpoint = listOf(
                    ServiceEndpoint(
                        id = "${did.id}#didcomm-1",
                        type = "wallet-endpoint",
                        serviceEndpoint = listOf(it.endpointUrl)
                    )
                )
            }
        }
    }

    interface DidServicePlugin {
        fun createDid(keyAlias: String?): Did
        fun loadDid(uri: String): Did
        fun loadDidDoc(uri: String): WaltIdDid
        fun resolveDid(uri: String): Did?
        fun resolveDidDoc(uri: String): WaltIdDid?
        fun importDid(did: Did): KeyId
        fun removeDid(did: Did)
    }

    object DidKeyPlugin: DidServicePlugin {

        override fun createDid(keyAlias: String?): Did {
            val nessusKeyAlgorithm = DEFAULT_KEY_ALGORITHM
            val waltKeyAlgorithm = nessusKeyAlgorithm.toWaltIdKeyAlgorithm()
            val keyId = keyAlias?.let { KeyId(it) } ?: cryptoService.generateKey(waltKeyAlgorithm)
            val key = keyStore.load(keyId.id)

            val pubkeyBytes = key.getPublicKey().convertEd25519toRaw()
            val identifier = convertRawKeyToMultiBase58Btc(pubkeyBytes, getMulticodecKeyCode(waltKeyAlgorithm))
            val verkey = pubkeyBytes.encodeBase58()

            val did = Did(identifier, DidMethod.KEY, nessusKeyAlgorithm, verkey)

            val didDoc = WaltIdDidService.resolve(did.uri)
            WaltIdDidService.storeDid(did.uri, didDoc.encodePretty())

            appendKeyStoreAliases(keyId, did, didDoc)

            return did
        }

        override fun loadDid(uri: String): Did {
            return fromWaltIdDid(loadDidDoc(uri))
        }

        override fun loadDidDoc(uri: String): WaltIdDid {
            return WaltIdDidService.load(uri)
        }

        override fun resolveDid(uri: String): Did {
            return fromWaltIdDid(resolveDidDoc(uri))
        }

        override fun resolveDidDoc(uri: String): WaltIdDid {
            return WaltIdDidService.resolve(uri)
        }

        override fun importDid(did: Did): KeyId {
            WaltIdDidService.importDidAndKeys(did.uri)
            val didDoc = WaltIdDidService.resolve(did.uri)
            val keyId = keyStore.load(did.uri).keyId
            appendKeyStoreAliases(keyId, did, didDoc)
            return keyId
        }

        override fun removeDid(did: Did) {
            WaltIdDidService.deleteDid(did.uri)
        }
    }

    object DidPeerPlugin: DidServicePlugin {

        override fun createDid(keyAlias: String?): Did {
            val nessusKeyAlgorithm = DEFAULT_KEY_ALGORITHM
            val waltKeyAlgorithm = nessusKeyAlgorithm.toWaltIdKeyAlgorithm()
            val keyId = keyAlias?.let { KeyId(it) } ?: cryptoService.generateKey(waltKeyAlgorithm)
            val key = keyStore.load(keyId.id)

            val pubkeyBytes = key.getPublicKey().convertEd25519toRaw()
            val identifier = convertRawKeyToMultiBase58Btc(pubkeyBytes, getMulticodecKeyCode(waltKeyAlgorithm))
            val verkey = pubkeyBytes.encodeBase58()

            val did = Did("0$identifier", DidMethod.PEER, nessusKeyAlgorithm, verkey)

            val didDoc = constructWaltIdDid(did, pubkeyBytes)
            WaltIdDidService.storeDid(did.uri, didDoc.encodePretty())

            appendKeyStoreAliases(keyId, did, didDoc)

            return did
        }

        override fun loadDid(uri: String): Did {
            return fromWaltIdDid(loadDidDoc(uri))
        }

        override fun loadDidDoc(uri: String): WaltIdDid {
            return WaltIdDidService.load(uri)
        }

        override fun resolveDid(uri: String): Did {
            return fromWaltIdDid(resolveDidDoc(uri))
        }

        override fun resolveDidDoc(uri: String): WaltIdDid {
            val keyId = keyStore.getKeyId(uri)?.let { KeyId(it) } ?: run {
                val didUrl = DidUrl.from(uri)
                val id = didUrl.identifier.substring(1)
                val pubkeyBytes = convertMultiBase58BtcToRawKey(id)
                storePubkeyBytes(pubkeyBytes)
            }
            return resolveFromKey(keyStore.load(keyId.id))
        }

        override fun importDid(did: Did): KeyId {
            val keyId = keyStore.getKeyId(did.uri)?.let { KeyId(it) } ?: run {
                val pubkeyBytes = did.verkey.decodeBase58()
                storePubkeyBytes(pubkeyBytes)
            }

            val didDoc = resolveFromKey(keyStore.load(keyId.id))
            WaltIdDidService.storeDid(did.uri, didDoc.encodePretty())

            appendKeyStoreAliases(keyId, did, didDoc)
            return keyId
        }

        override fun removeDid(did: Did) {
            try {
                val didDoc = WaltIdDidService.load(did.uri)
                ContextManager.hkvStore.delete(HKVKey("did", "created", did.uri), recursive = true)
                didDoc.verificationMethod?.forEach { ContextManager.keyStore.delete(it.id) }
            } catch (e: Exception) {
                log.error(e) { "Cannot remove did: ${did.uri}" }
            }
        }

        private fun resolveFromKey(key: Key): WaltIdDid {

            val pubkeyBytes = key.getPublicKey().convertEd25519toRaw()
            val identifier = convertRawKeyToMultiBase58Btc(pubkeyBytes, getMulticodecKeyCode(key.algorithm))
            val verkey = pubkeyBytes.encodeBase58()

            val algorithm = KeyAlgorithm.fromWaltIdKeyAlgorithm(key.algorithm)
            val did = Did("0$identifier", DidMethod.PEER, algorithm, verkey)

            return constructWaltIdDid(did, pubkeyBytes)
        }
    }

    object DidSovPlugin: DidServicePlugin {

        override fun createDid(keyAlias: String?): Did {

            val nessusKeyAlgorithm = DEFAULT_KEY_ALGORITHM
            val waltKeyAlgorithm = nessusKeyAlgorithm.toWaltIdKeyAlgorithm()
            val keyId = keyAlias?.let { KeyId(it) } ?: cryptoService.generateKey(waltKeyAlgorithm)
            val key = keyStore.load(keyId.id)

            val pubkeyBytes = key.getPublicKey().convertEd25519toRaw()
            val identifierBytes = pubkeyBytes.dropLast(16).toByteArray()
            val identifier =  identifierBytes.encodeBase58()
            val verkey = pubkeyBytes.encodeBase58()

            val did = Did(identifier, DidMethod.SOV, nessusKeyAlgorithm, verkey)

            val didDoc = constructWaltIdDid(did, pubkeyBytes)
            WaltIdDidService.storeDid(did.uri, didDoc.encodePretty())

            appendKeyStoreAliases(keyId, did, didDoc)

            return did
        }

        override fun loadDid(uri: String): Did {
            return fromWaltIdDid(loadDidDoc(uri))
        }

        override fun loadDidDoc(uri: String): WaltIdDid {
            return WaltIdDidService.load(uri)
        }

        override fun resolveDid(uri: String): Did? {
            return resolveDidDoc(uri)?.let { fromWaltIdDid(it) }
        }

        override fun resolveDidDoc(uri: String): WaltIdDid? {
            // We can resolve the Did Document when we have the public key
            return keyStore.getKeyId(uri)?.let {
                resolveFromKey(keyStore.load(it))
            }
        }

        override fun importDid(did: Did): KeyId {
            val keyId = keyStore.getKeyId(did.uri)?.let { KeyId(it) } ?: run {
                val pubkeyBytes = did.verkey.decodeBase58()
                storePubkeyBytes(pubkeyBytes)
            }

            val didDoc = resolveFromKey(keyStore.load(keyId.id))
            WaltIdDidService.storeDid(did.uri, didDoc.encodePretty())

            appendKeyStoreAliases(keyId, did, didDoc)
            return keyId
        }

        override fun removeDid(did: Did) {
            try {
                val didDoc = WaltIdDidService.load(did.uri)
                ContextManager.hkvStore.delete(HKVKey("did", "created", did.uri), recursive = true)
                didDoc.verificationMethod?.forEach { ContextManager.keyStore.delete(it.id) }
            } catch (e: Exception) {
                log.error(e) { "Cannot remove did: ${did.uri}" }
            }
        }

        private fun resolveFromKey(key: Key): WaltIdDid {

            val pubkeyBytes = key.getPublicKey().convertEd25519toRaw()
            val identifierBytes = pubkeyBytes.dropLast(16).toByteArray()
            val identifier = identifierBytes.encodeBase58()
            val verkey = pubkeyBytes.encodeBase58()

            val algorithm = KeyAlgorithm.fromWaltIdKeyAlgorithm(key.algorithm)
            val did = Did(identifier, DidMethod.SOV, algorithm, verkey)

            return constructWaltIdDid(did, pubkeyBytes)
        }
    }

    private fun appendKeyStoreAliases(keyId: KeyId, did: Did, didDoc: WaltIdDid?) {

        keyStore.addAlias(keyId, did.uri)
        keyStore.addAlias(keyId, did.verkey)

        didDoc?.verificationMethod?.forEach { vm ->
            keyStore.addAlias(keyId, vm.id)
        }
    }

    private fun storePubkeyBytes(pubkeyBytes: ByteArray): KeyId {
        val key = buildKey(
            keyId = newKeyId().id,
            algorithm = "EdDSA_Ed25519",
            provider = "SUN",
            publicPart = pubkeyBytes.encodeBase64(),
            privatePart = null,
            format = KeyFormat.BASE64_RAW
        )
        keyStore.store(key)
        return key.keyId
    }

    private fun constructWaltIdDid(did: Did, pubKey: ByteArray): WaltIdDid {
        check(did.algorithm == KeyAlgorithm.EdDSA_Ed25519) { "Unsupported key algorithm: $did" }

        val (keyAgreementKeys, verificationMethods, keyRef) = generateEdParams(did, pubKey)

        return WaltIdDid(
            context = DID_CONTEXT_URL,
            id = did.uri,
            verificationMethod = verificationMethods,
            authentication = keyRef,
            assertionMethod = keyRef,
            capabilityDelegation = keyRef,
            capabilityInvocation = keyRef,
            keyAgreement = keyAgreementKeys,
            serviceEndpoint = null
        )
    }

    private fun generateEdParams(did: Did, pubKey: ByteArray): Triple<List<VerificationMethod>?, MutableList<VerificationMethod>, List<VerificationMethod>> {

        val dhKey = convertPublicKeyEd25519ToCurve25519(pubKey)
        val dhKeyMb = convertX25519PublicKeyToMultiBase58Btc(dhKey)

        val dhKeyId = did.uri + "#" + dhKeyMb
        val pubKeyId = did.uri + "#" + did.id

        val verificationMethods = mutableListOf(
            VerificationMethod(pubKeyId, LdVerificationKeyType.Ed25519VerificationKey2019.name, did.uri, pubKey.encodeBase58()),
            VerificationMethod(dhKeyId, "X25519KeyAgreementKey2019", did.uri, dhKey.encodeBase58())
        )

        return Triple(
            listOf(VerificationMethod.Reference(dhKeyId)),
            verificationMethods,
            listOf(VerificationMethod.Reference(pubKeyId))
        )
    }
}
