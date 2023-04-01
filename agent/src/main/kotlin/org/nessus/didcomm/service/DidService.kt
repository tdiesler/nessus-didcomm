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
import id.walt.services.did.DidService.storeDid
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
import org.nessus.didcomm.service.LazySodiumService.convertEd25519toRaw
import org.nessus.didcomm.model.DEFAULT_KEY_ALGORITHM
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.Did.Companion.didMethod
import org.nessus.didcomm.model.DidDoc
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.DidPeer
import org.nessus.didcomm.model.KeyAlgorithm
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeBase64
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.trimJson

typealias WaltIdDidService = id.walt.services.did.DidService
typealias WaltIdDidMethod = id.walt.model.DidMethod
typealias WaltIdDidDoc = id.walt.model.Did
typealias WaltIdDid = id.walt.model.Did

/** Common Did document options */
open class DidOptions(
    val endpointUrl: String?,
) {
    override fun toString() = "DidOptions(endpointUrl=$endpointUrl)"
}

class DidPeerOptions(
    val numalgo: Int = 0,
    endpointUrl: String? = null,
): DidOptions(endpointUrl) {
    override fun toString() = "DidPeerOptions(numalgo=$numalgo, endpointUrl=$endpointUrl)"
}

interface DidServicePlugin {
    fun createDid(keyAlias: String?, options: DidOptions?): Did
    fun loadDid(uri: String): Did
    fun loadDidDoc(uri: String): WaltIdDidDoc
    fun resolveDid(uri: String): Did?
    fun resolveDidDoc(uri: String): WaltIdDidDoc?
    fun importDid(did: Did): KeyId
    fun importDidDoc(didDoc: WaltIdDidDoc): KeyId
    fun deleteDid(did: Did) {}
}

fun WaltIdDidDoc.findServiceEndpoint(): String? {
    return service?.firstOrNull()?.serviceEndpoint?.firstOrNull()
}

fun WaltIdDidDoc.withServiceEndpoint(uri: String, endpointUrl: String? = null) = apply {

    // Check already existing serviceEndpoint
    if (findServiceEndpoint() != null)
        return this

    // Use given endpointUrl or from a wallet (when found)
    val serviceEndpoint = if (endpointUrl != null) {
        endpointUrl
    } else {
        val modelService = ModelService.getService()
        modelService.findWalletByDid(uri)?.endpointUrl
    }

    // Assign a new service endpoint
    // Note, WaltIdDidDoc is mutable
    if (serviceEndpoint != null) {
        service = listOf(
            ServiceEndpoint(
                id = "$uri#didcomm-1",
                type = "DIDCommMessaging",
                serviceEndpoint = listOf(serviceEndpoint)
            )
        )
    }
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

    /**
     * A Did may be given an endpointUrl at create time, which is then stored as part of the DidDoc
     */
    fun createDid(method: DidMethod, keyAlias: String? = null, options: DidOptions? = null): Did {
        val did = withPlugin(method).createDid(keyAlias, options)
        log.info { "Created DidDoc: ${loadDidDoc(did.uri).encodeJson(true)}" }
        return did
    }

    fun deleteDid(did: Did) {
        if (hasDid(did.uri)) {
            WaltIdDidService.deleteDid(did.uri)
            keyStore.getKeyId(did.uri)?.also { keyStore.delete(it) }
        }
        withPlugin(did.method).deleteDid(did)
    }

    fun hasDid(uri: String): Boolean {
        return WaltIdDidService.loadDid(uri) != null
    }

    /**
     * Loads a Did that is required to exist in store
     */
    fun loadDid(uri: String): Did {
        return withPlugin(didMethod(uri)).loadDid(uri)
    }

    /**
     * Loads a DidDoc that is required to exist in store
     */
    fun loadDidDoc(uri: String): DidDoc {
        val waltDidDoc = withPlugin(didMethod(uri)).loadDidDoc(uri)
        return DidDoc.fromWaltIdDidDoc(waltDidDoc.withServiceEndpoint(uri))
    }

    fun loadOrResolveDid(uri: String): Did? {
        return when {
            hasDid(uri) -> loadDid(uri)
            else -> resolveDid(uri)
        }
    }

    fun loadOrResolveDidDoc(uri: String): DidDoc? {
        return when {
            hasDid(uri) -> loadDidDoc(uri)
            else -> resolveDidDoc(uri)
        }
    }

    fun resolveDid(uri: String): Did? {
        val waltDidDoc = withPlugin(didMethod(uri)).resolveDidDoc(uri)
        return waltDidDoc?.let { didFromDidDoc(it) }
    }

    fun resolveDidDoc(uri: String): DidDoc? {
        val waltDidDoc = withPlugin(didMethod(uri)).resolveDidDoc(uri)
        return waltDidDoc?.let { DidDoc.fromWaltIdDidDoc(it.withServiceEndpoint(uri)) }
    }

    fun importDid(did: Did): KeyId {
        return withPlugin(did.method).importDid(did)
    }

    fun importDidDoc(didDoc: DidDoc): KeyId {
        val method = didMethod(didDoc.id)
        val encodedDoc = didDoc.encodeJson()
        val waltDidDoc = WaltIdDidDoc.decode(encodedDoc)
        checkNotNull(waltDidDoc?.findServiceEndpoint()) { "No serviceEndpoint in: ${waltDidDoc?.encodeJson()}" }
        return withPlugin(method).importDidDoc(waltDidDoc!!)
    }

    // Private ---------------------------------------------------------------------------------------------------------

    object DidKeyPlugin: DidServicePlugin {
        val log = KotlinLogging.logger {}

        override fun createDid(keyAlias: String?, options: DidOptions?): Did {

            val nessusKeyAlgorithm = DEFAULT_KEY_ALGORITHM
            val waltKeyAlgorithm = nessusKeyAlgorithm.toWaltIdKeyAlgorithm()
            val keyId = keyAlias?.let { KeyId(it) } ?: cryptoService.generateKey(waltKeyAlgorithm)
            val key = keyStore.load(keyId.id)

            val pubkeyBytes = key.getPublicKey().convertEd25519toRaw()
            val verkey = pubkeyBytes.encodeBase58()

            val identifier = convertRawKeyToMultiBase58Btc(pubkeyBytes, getMulticodecKeyCode(waltKeyAlgorithm))
            val did = Did(identifier, DidMethod.KEY, verkey)

            val waltDidDoc = WaltIdDidService.resolve(did.uri)
            storeDid(waltDidDoc.withServiceEndpoint(did.uri, options?.endpointUrl))

            val didDocV2 = DidDoc.fromWaltIdDidDoc(waltDidDoc)
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

            // Store verification key
            WaltIdDidService.importDidAndKeys(did.uri)
            val keyId = keyStore.load(did.uri).keyId

            // Generate WaltIdDidDoc
            val didDoc = WaltIdDidService.resolve(did.uri)

            // Store the generated DidDoc
            storeDid(didDoc)

            // Store key aliases referenced from the DidDoc
            val didDocV2 = DidDoc.fromWaltIdDidDoc(didDoc)
            appendKeyStoreAliases(keyId, did, didDocV2)

            return keyId
        }

        override fun importDidDoc(didDoc: WaltIdDidDoc): KeyId {

            // Construct the Did from the DidDoc
            val did = didFromDidDoc(didDoc)

            // Store verification key
            WaltIdDidService.importDidAndKeys(did.uri)
            val keyId = keyStore.load(did.uri).keyId

            // Store the given DidDoc
            storeDid(didDoc)

            // Store key aliases referenced from the DidDoc
            val didDocV2 = DidDoc.fromWaltIdDidDoc(didDoc)
            appendKeyStoreAliases(keyId, did, didDocV2)

            return keyId
        }
    }

    object DidPeerPlugin: DidServicePlugin {

        override fun createDid(keyAlias: String?, options: DidOptions?): Did {
            requireNotNull(options) { "No did:peer options" }

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

            val (did, waltDidDoc) = when((options as DidPeerOptions).numalgo) {

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
                    )
                    Pair(did, didDoc)
                }

                2 -> {
                    val service = options.endpointUrl?.let { endpointUrl ->
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

                else -> throw IllegalArgumentException("Unsupported numalgo: ${options.numalgo}")
            }

            check(isPeerDID(did.uri)) { "Not a did:peer: ${did.uri}" }
            checkNotNull(waltDidDoc) { "Cannot resolve: ${did.uri}" }

            storeDid(waltDidDoc.withServiceEndpoint(did.uri, options.endpointUrl))
            storeDid(waltDidDoc)

            val didDocV2 = DidDoc.fromWaltIdDidDoc(waltDidDoc)
            appendKeyStoreAliases(keyId, did, didDocV2)

            return did
        }

        override fun loadDid(uri: String): DidPeer {
            val did = didFromDidDoc(loadDidDoc(uri))
            return DidPeer(did.id, did.method, did.verkey)
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

            // Store verification key
            val keyId = keyStore.getKeyId(did.uri)?.let { KeyId(it) } ?: run {
                val pubkeyBytes = did.verkey.decodeBase58()
                storePubkeyBytes(pubkeyBytes)
            }

            // Generate WaltIdDidDoc
            val didDoc =  WaltIdDidDoc.decode(resolvePeerDID(did.uri))

            // Store the generated DidDoc
            storeDid(didDoc!!)

            // Store key aliases referenced from the DidDoc
            val didDocV2 = DidDoc.fromWaltIdDidDoc(didDoc)
            appendKeyStoreAliases(keyId, did, didDocV2)

            return keyId
        }

        override fun importDidDoc(didDoc: WaltIdDidDoc): KeyId {

            // Construct the Did from the DidDoc
            val did = didFromDidDoc(didDoc)

            // Store verification key
            val keyId = keyStore.getKeyId(did.uri)?.let { KeyId(it) } ?: run {
                val pubkeyBytes = did.verkey.decodeBase58()
                storePubkeyBytes(pubkeyBytes)
            }

            // Store the given DidDoc
            storeDid(didDoc)

            // Store key aliases referenced from the DidDoc
            val didDocV2 = DidDoc.fromWaltIdDidDoc(didDoc)
            appendKeyStoreAliases(keyId, did, didDocV2)

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

        override fun createDid(keyAlias: String?, options: DidOptions?): Did {

            val nessusKeyAlgorithm = DEFAULT_KEY_ALGORITHM
            val waltKeyAlgorithm = nessusKeyAlgorithm.toWaltIdKeyAlgorithm()
            val keyId = keyAlias?.let { KeyId(it) } ?: cryptoService.generateKey(waltKeyAlgorithm)
            val key = keyStore.load(keyId.id)

            val pubkeyBytes = key.getPublicKey().convertEd25519toRaw()
            val identifierBytes = pubkeyBytes.dropLast(16).toByteArray()
            val identifier =  identifierBytes.encodeBase58()
            val verkey = pubkeyBytes.encodeBase58()

            val did = Did(identifier, DidMethod.SOV, verkey)

            val waltDidDoc = generateWaltIdDidDoc(did, pubkeyBytes)
            storeDid(waltDidDoc.withServiceEndpoint(did.uri, options?.endpointUrl))

            val didDocV2 = DidDoc.fromWaltIdDidDoc(waltDidDoc)
            appendKeyStoreAliases(keyId, did, didDocV2)

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

            // Store verification key
            val keyId = keyStore.getKeyId(did.uri)?.let { KeyId(it) } ?: run {
                val pubkeyBytes = did.verkey.decodeBase58()
                storePubkeyBytes(pubkeyBytes)
            }

            // Generate WaltIdDidDoc
            val didDoc = resolveFromKey(keyStore.load(keyId.id))

            // Store the generated DidDoc
            storeDid(didDoc)

            // Store key aliases referenced from the DidDoc
            val didDocV2 = DidDoc.fromWaltIdDidDoc(didDoc)
            appendKeyStoreAliases(keyId, did, didDocV2)

            return keyId
        }

        override fun importDidDoc(didDoc: WaltIdDidDoc): KeyId {

            // Construct the Did from the DidDoc
            val did = didFromDidDoc(didDoc)

            // Store verification key
            val keyId = keyStore.getKeyId(did.uri)?.let { KeyId(it) } ?: run {
                val pubkeyBytes = did.verkey.decodeBase58()
                storePubkeyBytes(pubkeyBytes)
            }

            // Store the given DidDoc
            storeDid(didDoc)

            // Store key aliases referenced from the DidDoc
            val didDocV2 = DidDoc.fromWaltIdDidDoc(didDoc)
            appendKeyStoreAliases(keyId, did, didDocV2)

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

    private fun appendKeyStoreAliases(keyId: KeyId, did: Did, didDoc: DidDoc) {
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

    private fun didFromDidDoc(didDoc: WaltIdDidDoc): Did {
        val verificationMethod = didDoc.authentication?.firstOrNull { it.type.startsWith("Ed25519") }
            ?: didDoc.verificationMethod?.firstOrNull { it.type.startsWith("Ed25519") }
        checkNotNull(verificationMethod) {"No suitable verification method: ${didDoc.encode()}"}
        val verkey = when {
            verificationMethod.publicKeyBase58 != null -> {
                verificationMethod.publicKeyBase58
            }
            verificationMethod.publicKeyMultibase != null -> {
                val verkeyBytes = convertMultiBase58BtcToRawKey(verificationMethod.publicKeyMultibase!!)
                verkeyBytes.encodeBase58()
            }
            else -> throw IllegalStateException("Unsupported public key encoding")
        }
        checkNotNull(verkey) {"No verkey in: ${verificationMethod.id}"}
        return Did.fromUri(verificationMethod.controller, verkey)
    }
}

