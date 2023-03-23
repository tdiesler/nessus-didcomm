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
import id.walt.crypto.LdVerificationKeyType.Ed25519VerificationKey2018
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
import id.walt.model.ServiceEndpoint
import id.walt.model.VerificationMethod
import id.walt.services.context.ContextManager
import id.walt.services.hkvstore.HKVKey
import id.walt.services.keystore.KeyStoreService
import mu.KotlinLogging
import org.didcommx.peerdid.VerificationMaterialAgreement
import org.didcommx.peerdid.VerificationMaterialAuthentication
import org.didcommx.peerdid.VerificationMaterialFormatPeerDID
import org.didcommx.peerdid.VerificationMethodTypeAgreement
import org.didcommx.peerdid.VerificationMethodTypeAuthentication
import org.didcommx.peerdid.createPeerDIDNumalgo0
import org.didcommx.peerdid.createPeerDIDNumalgo2
import org.didcommx.peerdid.isPeerDID
import org.didcommx.peerdid.resolvePeerDID
import org.nessus.didcomm.crypto.LazySodiumService.convertEd25519toRaw
import org.nessus.didcomm.did.DEFAULT_KEY_ALGORITHM
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.Did.Companion.didMethod
import org.nessus.didcomm.did.DidDocV2
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.did.DidPeer
import org.nessus.didcomm.did.KeyAlgorithm
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeBase64
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.trimJson


typealias WaltIdDidService = id.walt.services.did.DidService
typealias WaltIdDidMethod = id.walt.model.DidMethod
typealias WaltIdDidDoc = id.walt.model.Did
typealias WaltIdDid = id.walt.model.Did

/** Abstract Did create options */
open class DidCreateOptions {
    override fun toString() = "DidCreateOptions()"
}

data class DidPeerOptions(
    val numalgo: Int? = null,
    val serviceEndpoint: String? = null,
): DidCreateOptions()

interface DidServicePlugin {
    fun createDid(keyAlias: String?, options: DidCreateOptions? = null): Did
    fun loadDid(uri: String): Did
    fun loadDidDoc(uri: String): WaltIdDidDoc
    fun resolveDid(uri: String): Did?
    fun resolveDidDoc(uri: String): WaltIdDidDoc?
    fun importDid(did: Did): KeyId
    fun deleteDid(did: Did) {}
}

object DidService: ObjectService<DidService>() {
    val log = KotlinLogging.logger {}

    override fun getService() = apply { }

    private val modelService get() = ModelService.getService()
    private val cryptoService get() = NessusCryptoService.getService()
    private val keyStore get() = KeyStoreService.getService()

    private fun withPlugin(method: DidMethod): DidServicePlugin {
        return when(method) {
            DidMethod.KEY -> DidKeyPlugin
            DidMethod.PEER -> DidPeerPlugin
            DidMethod.SOV -> DidSovPlugin
        }
    }

    fun createDid(method: DidMethod, keyAlias: String? = null, options: DidCreateOptions? = null): Did {
        val did = withPlugin(method).createDid(keyAlias, options)
        val didDoc = loadDidDocument(did.uri)
        log.info { "Created Did: ${didDoc.encodeJson(true)}" }
        return did
    }

    fun deleteDid(did: Did) {
        WaltIdDidService.deleteDid(did.uri)
        withPlugin(did.method).deleteDid(did)
    }

    fun hasDid(uri: String): Boolean {
        return try { WaltIdDidService.load(uri); true }
        catch (e: RuntimeException) { false }
    }

    fun loadDid(uri: String): Did {
        return withPlugin(didMethod(uri)).loadDid(uri)
    }

    fun loadDidDocument(uri: String): DidDocV2 {
        val didDoc = withPlugin(didMethod(uri)).loadDidDoc(uri)
            .also { addWalletServiceEndpoint(it) }
        return DidDocV2.fromWaltIdDidDoc(didDoc)
    }

    fun loadOrResolveDid(uri: String): Did? {
        return if (hasDid(uri))
            loadDid(uri)
        else
            resolveDid(uri)
    }

    fun loadOrResolveDidDocument(uri: String): DidDocV2? {
        return if (hasDid(uri))
            loadDidDocument(uri)
        else
            resolveDidDocument(uri)
    }

    fun resolveDid(uri: String): Did? {
        return withPlugin(didMethod(uri)).resolveDid(uri)
    }

    fun resolveDidDocument(uri: String): DidDocV2? {
        return withPlugin(didMethod(uri)).resolveDidDoc(uri)
            ?.also { addWalletServiceEndpoint(it) }
            ?.let { DidDocV2.fromWaltIdDidDoc(it) }
    }

    fun importDid(did: Did): KeyId {
        return withPlugin(did.method).importDid(did)
    }

    // Private ---------------------------------------------------------------------------------------------------------

    object DidKeyPlugin: DidServicePlugin {
        val log = KotlinLogging.logger {}

        override fun createDid(keyAlias: String?, options: DidCreateOptions?): Did {
            require(options == null) { "Options not supported for did:key: $options" }

            val nessusKeyAlgorithm = DEFAULT_KEY_ALGORITHM
            val waltKeyAlgorithm = nessusKeyAlgorithm.toWaltIdKeyAlgorithm()
            val keyId = keyAlias?.let { KeyId(it) } ?: cryptoService.generateKey(waltKeyAlgorithm)
            val key = keyStore.load(keyId.id)

            val pubkeyBytes = key.getPublicKey().convertEd25519toRaw()
            val verkey = pubkeyBytes.encodeBase58()

            val identifier = convertRawKeyToMultiBase58Btc(pubkeyBytes, getMulticodecKeyCode(waltKeyAlgorithm))
            val did = Did(identifier, DidMethod.KEY, verkey)

            val didDocV2 = DidDocV2.fromWaltIdDidDoc(WaltIdDidService.resolve(did.uri))
            storeDid(did.uri, didDocV2.encodeJson(true))

            appendKeyStoreAliases(keyId, did, didDocV2)

            return did
        }

        override fun loadDid(uri: String): Did {
            return didFromDidDoc(loadDidDoc(uri))
        }

        override fun loadDidDoc(uri: String): WaltIdDid {
            return WaltIdDidService.load(uri)
        }

        override fun resolveDid(uri: String): Did {
            return didFromDidDoc(resolveDidDoc(uri))
        }

        override fun resolveDidDoc(uri: String): WaltIdDid {
            return WaltIdDidService.resolve(uri)
        }

        override fun importDid(did: Did): KeyId {
            WaltIdDidService.importDidAndKeys(did.uri)
            val keyId = keyStore.load(did.uri).keyId
            val didDoc = DidDocV2.fromWaltIdDidDoc(WaltIdDidService.resolve(did.uri))
            appendKeyStoreAliases(keyId, did, didDoc)
            return keyId
        }
    }

    object DidPeerPlugin: DidServicePlugin {

        override fun createDid(keyAlias: String?, options: DidCreateOptions?): Did {

            val nessusKeyAlgorithm = KeyAlgorithm.EdDSA_Ed25519
            val waltKeyAlgorithm = nessusKeyAlgorithm.toWaltIdKeyAlgorithm()
            val keyId = keyAlias?.let { KeyId(it) } ?: cryptoService.generateKey(waltKeyAlgorithm)
            val key = keyStore.load(keyId.id)

            val pubkeyBytes = key.getPublicKey().convertEd25519toRaw()
            val publicSigningKey = pubkeyBytes.encodeBase58()
            val publicEncryptionKey = convertPublicKeyEd25519ToCurve25519(pubkeyBytes).encodeBase58()

            val signingKey = VerificationMaterialAuthentication(
                value = publicSigningKey,
                type = VerificationMethodTypeAuthentication.ED25519_VERIFICATION_KEY_2018,
                format = VerificationMaterialFormatPeerDID.BASE58
            )
            val encryptionKey = VerificationMaterialAgreement(
                value = publicEncryptionKey,
                type = VerificationMethodTypeAgreement.X25519_KEY_AGREEMENT_KEY_2019,
                format = VerificationMaterialFormatPeerDID.BASE58
            )

            fun didUriToDid(didUri: String): Did {
                val identifier = didUri.substring(9)
                return Did(identifier, DidMethod.PEER, publicSigningKey)
            }

            val peerOptions = options as? DidPeerOptions ?: DidPeerOptions(0)

            val (did, didDoc) = when(peerOptions.numalgo) {

                0 -> {
                    val did = didUriToDid(createPeerDIDNumalgo0(signingKey))
                    // Note, PeerDidDoc does not contain an encryption key
                    // val didDoc = WaltIdDidDoc.decode(resolvePeerDID(did.uri))
                    val authenticationId = did.uri + "#" + did.id
                    val keyAgreementId = did.uri + "#" + encryptionKey.value
                    val verificationMethods = listOf(
                        VerificationMethod(authenticationId, Ed25519VerificationKey2018.name, did.uri, publicKeyBase58 = publicSigningKey),
                        VerificationMethod(keyAgreementId, "X25519KeyAgreementKey2019", did.uri, publicKeyBase58 = publicEncryptionKey)
                    )
                    val didDoc = WaltIdDidDoc(
                        id = did.uri,
                        context = DID_CONTEXT_URL,
                        verificationMethod = verificationMethods,
                        authentication = listOf(VerificationMethod.Reference(authenticationId)),
                        keyAgreement = listOf(VerificationMethod.Reference(keyAgreementId)),
                        serviceEndpoint = null
                    )
                    Pair(did, didDoc)
                }

                2 -> {
                    val service = peerOptions.serviceEndpoint?.let { endpointUrl ->
                        """
                        { 
                            "type": "DIDCommMessaging", 
                            "serviceEndpoint": "$endpointUrl" 
                        }
                        """.trimJson()
                    }
                    val did = didUriToDid(createPeerDIDNumalgo2(listOf(encryptionKey), listOf(signingKey), service))
                    val didDoc = WaltIdDidDoc.decode(fixupDidDoc(resolvePeerDID(did.uri)))
                    Pair(did, didDoc)
                }

                else -> throw IllegalArgumentException("Unsupported numalgo: ${peerOptions.numalgo}")
            }

            check(isPeerDID(did.uri)) { "Not a did:peer: ${did.uri}" }
            checkNotNull(didDoc) { "Cannot resolve: ${did.uri}" }

            val didDocV2 = DidDocV2.fromWaltIdDidDoc(didDoc)
            storeDid(did.uri, didDocV2.encodeJson(true))
            appendKeyStoreAliases(keyId, did, didDocV2)

            return did
        }

        override fun loadDid(uri: String): DidPeer {
            return didFromDidDoc(loadDidDoc(uri))
        }

        override fun loadDidDoc(uri: String): WaltIdDidDoc {
            return WaltIdDidService.load(uri)
        }

        override fun resolveDid(uri: String): Did? {
            return resolveDidDoc(uri)?.let { didFromDidDoc(it) }
        }

        override fun resolveDidDoc(uri: String): WaltIdDidDoc? {
            val peerDidDoc = fixupDidDoc(resolvePeerDID(uri))
            return WaltIdDidDoc.decode(peerDidDoc)
        }

        override fun importDid(did: Did): KeyId {
            val didDoc = resolveDidDoc(did.uri)
            checkNotNull(didDoc) { "Cannot resolve: ${did.uri}" }

            val pubKeyBytes = did.verkey.decodeBase58()
            val keyId = storePubkeyBytes(pubKeyBytes)

            storeDid(did.uri, didDoc.encodePretty())
            appendKeyStoreAliases(keyId, did, DidDocV2.fromWaltIdDidDoc(didDoc))

            return keyId
        }

        // Did Document @context not optional in WaltId
        // https://github.com/walt-id/waltid-ssikit/issues/251
        private fun fixupDidDoc(didDoc: String): String {
            val decoded = didDoc.decodeJson().toMutableMap()
            if ("@context" !in decoded) {
                decoded["@context"] = DID_CONTEXT_URL
            }
            return decoded.encodeJson()
        }

        private fun resolveFromKey(key: Key): WaltIdDid {

            val pubkeyBytes = key.getPublicKey().convertEd25519toRaw()
            val identifier = convertRawKeyToMultiBase58Btc(pubkeyBytes, getMulticodecKeyCode(key.algorithm))
            val verkey = pubkeyBytes.encodeBase58()

            val did = Did("0$identifier", DidMethod.PEER, verkey)

            return generateWaltIdDidDoc(did, pubkeyBytes)
        }
    }

    object DidSovPlugin: DidServicePlugin {

        override fun createDid(keyAlias: String?, options: DidCreateOptions?): Did {
            require(options == null) { "Options not supported for did:sov: $options" }

            val nessusKeyAlgorithm = DEFAULT_KEY_ALGORITHM
            val waltKeyAlgorithm = nessusKeyAlgorithm.toWaltIdKeyAlgorithm()
            val keyId = keyAlias?.let { KeyId(it) } ?: cryptoService.generateKey(waltKeyAlgorithm)
            val key = keyStore.load(keyId.id)

            val pubkeyBytes = key.getPublicKey().convertEd25519toRaw()
            val identifierBytes = pubkeyBytes.dropLast(16).toByteArray()
            val identifier =  identifierBytes.encodeBase58()
            val verkey = pubkeyBytes.encodeBase58()

            val did = Did(identifier, DidMethod.SOV, verkey)

            val didDoc = DidDocV2.fromWaltIdDidDoc(generateWaltIdDidDoc(did, pubkeyBytes))
            storeDid(did.uri, didDoc.encodeJson(true))

            appendKeyStoreAliases(keyId, did, didDoc)

            return did
        }

        override fun loadDid(uri: String): Did {
            return didFromDidDoc(loadDidDoc(uri))
        }

        override fun loadDidDoc(uri: String): WaltIdDid {
            return WaltIdDidService.load(uri)
        }

        override fun resolveDid(uri: String): Did? {
            return resolveDidDoc(uri)?.let { didFromDidDoc(it) }
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

            val didDoc = DidDocV2.fromWaltIdDidDoc(resolveFromKey(keyStore.load(keyId.id)))
            storeDid(did.uri, didDoc.encodeJson(true))

            appendKeyStoreAliases(keyId, did, didDoc)
            return keyId
        }

        private fun resolveFromKey(key: Key): WaltIdDid {

            val pubkeyBytes = key.getPublicKey().convertEd25519toRaw()
            val identifierBytes = pubkeyBytes.dropLast(16).toByteArray()
            val identifier = identifierBytes.encodeBase58()
            val verkey = pubkeyBytes.encodeBase58()

            val did = Did(identifier, DidMethod.SOV, verkey)

            return generateWaltIdDidDoc(did, pubkeyBytes)
        }
    }

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

    private fun appendKeyStoreAliases(keyId: KeyId, did: Did, didDoc: DidDocV2) {
        appendKeyStoreAliases(keyId, did, didDoc.verificationMethods.map { vm -> vm.id })
    }

    private fun appendKeyStoreAliases(keyId: KeyId, did: Did, verificationMethodKeyIds: List<String>?) {

        keyStore.addAlias(keyId, did.uri)
        keyStore.addAlias(keyId, did.verkey)

        verificationMethodKeyIds?.forEach { kid -> keyStore.addAlias(keyId, kid) }
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

    private fun generateWaltIdDidDoc(did: Did, pubKey: ByteArray): WaltIdDidDoc {

        val (keyAgreementRefs, authenticationRef, verificationMethods) = generateEdParams(did, pubKey)

        return WaltIdDidDoc(
            id = did.uri,
            context = DID_CONTEXT_URL,
            verificationMethod = verificationMethods,
            authentication = authenticationRef,
            keyAgreement = keyAgreementRefs,
            serviceEndpoint = null
        )
    }

    private fun generateEdParams(did: Did, pubKey: ByteArray): Triple<List<VerificationMethod>?, List<VerificationMethod>, List<VerificationMethod>> {

        val encryptionKey = convertPublicKeyEd25519ToCurve25519(pubKey)
        val keyAgreementMultibase = convertX25519PublicKeyToMultiBase58Btc(encryptionKey)

        val keyAgreementId = did.uri + "#" + keyAgreementMultibase
        val authenticationId = did.uri + "#" + did.id

        val verificationMethods = listOf(
            VerificationMethod(authenticationId, Ed25519VerificationKey2018.name, did.uri, publicKeyBase58 = pubKey.encodeBase58()),
            VerificationMethod(keyAgreementId, "X25519KeyAgreementKey2019", did.uri, publicKeyBase58 = encryptionKey.encodeBase58())
        )

        return Triple(
            listOf(VerificationMethod.Reference(keyAgreementId)),
            listOf(VerificationMethod.Reference(authenticationId)),
            verificationMethods)
    }

    private fun didFromDidDoc(didDoc: WaltIdDidDoc): DidPeer {
        val vmethod = didDoc.authentication?.firstOrNull { it.type.startsWith("Ed25519") }
            ?: didDoc.verificationMethod?.firstOrNull { it.type.startsWith("Ed25519") }
        checkNotNull(vmethod) {"No suitable verification method: ${didDoc.encode()}"}
        val verkey = when {
            vmethod.publicKeyBase58 != null -> {
                vmethod.publicKeyBase58
            }
            vmethod.publicKeyMultibase != null -> {
                val verkeyBytes = convertMultiBase58BtcToRawKey(vmethod.publicKeyMultibase!!)
                verkeyBytes.encodeBase58()
            }
            else -> throw IllegalStateException("Unsupported public key encoding")
        }
        checkNotNull(verkey) {"No verkey in: ${vmethod.id}"}
        val did = Did.fromUri(vmethod.controller, verkey)
        return DidPeer(did.id, did.method, did.verkey)
    }

    // Private in WaltIdDidService
    private fun storeDid(didUrlStr: String, didDoc: String) {
        ContextManager.hkvStore.put(HKVKey("did", "created", didUrlStr), didDoc)
    }

}
