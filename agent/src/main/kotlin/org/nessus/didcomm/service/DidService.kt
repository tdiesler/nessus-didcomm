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
import id.walt.model.DidUrl
import id.walt.model.VerificationMethod
import id.walt.services.did.DidService.storeDid
import id.walt.services.keystore.KeyStoreService
import mu.KotlinLogging
import org.didcommx.didcomm.diddoc.DIDCommService
import org.didcommx.peerdid.VerificationMaterialAgreement
import org.didcommx.peerdid.VerificationMaterialAuthentication
import org.didcommx.peerdid.VerificationMaterialFormatPeerDID
import org.didcommx.peerdid.VerificationMethodTypeAgreement
import org.didcommx.peerdid.VerificationMethodTypeAuthentication
import org.didcommx.peerdid.createPeerDIDNumalgo0
import org.didcommx.peerdid.createPeerDIDNumalgo2
import org.didcommx.peerdid.isPeerDID
import org.didcommx.peerdid.resolvePeerDID
import org.nessus.didcomm.model.DEFAULT_ACCEPT
import org.nessus.didcomm.model.DEFAULT_KEY_ALGORITHM
import org.nessus.didcomm.model.Did
import org.nessus.didcomm.model.Did.Companion.didMethod
import org.nessus.didcomm.model.DidDoc
import org.nessus.didcomm.model.DidMethod
import org.nessus.didcomm.model.DidPeer
import org.nessus.didcomm.model.KeyAlgorithm
import org.nessus.didcomm.model.SicpaDidDoc
import org.nessus.didcomm.model.WaltIdVerificationMethod
import org.nessus.didcomm.model.toVerificationMethod
import org.nessus.didcomm.service.LazySodiumService.convertEd25519toRaw
import org.nessus.didcomm.util.decodeJson
import org.nessus.didcomm.util.encodeBase64
import org.nessus.didcomm.util.encodeJson

// These are actually used
@Suppress("unused") typealias WaltIdDidService = id.walt.services.did.DidService
@Suppress("unused") typealias WaltIdDidMethod = id.walt.model.DidMethod

typealias WaltIdDidDoc = id.walt.model.Did
typealias WaltIdDid = id.walt.model.Did

/** Common Did document options */
open class DidOptions(
    val endpointUrl: String? = null,
    val routingKeys: List<String>? = null,
    val accept: List<String>? = null,
) {
    override fun toString() = "DidOptions(endpointUrl=$endpointUrl, routingKeys=$routingKeys, accept=$accept)"
}

class DidPeerOptions(
    val numalgo: Int = 0,
    endpointUrl: String? = null,
    routingKeys: List<String>? = null,
    accept: List<String>? = null,
): DidOptions(endpointUrl, routingKeys, accept) {
    override fun toString() = "DidPeerOptions(numalgo=$numalgo, endpointUrl=$endpointUrl, routingKeys=$routingKeys, accept=$accept)"
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

object DidService: ObjectService<DidService>() {
    val log = KotlinLogging.logger {}

    @JvmStatic
    fun getService() = apply { }

    private val modelService get() = ModelService.getService()
    private val cryptoService get() = NessusCryptoService.getService()
    private val keyStore get() = KeyStoreService.getService()

    // The ServiceEndpoint in WaltId is not rich enough to store all required properties
    private val serviceMapping = mutableMapOf<String, List<DIDCommService>>()

    /**
     * A Did may be given an endpointUrl at create time, which is then stored as part of the DidDoc
     */
    fun createDid(method: DidMethod, keyAlias: String? = null, options: DidOptions? = null): Did {
        val did = withPlugin(method).createDid(keyAlias, options)
        log.info { "Created DidDoc: ${loadDidDoc(did.uri).encodeJson(true)}" }
        return did
    }

    fun deleteDid(did: Did) {
        withPlugin(did.method).deleteDid(did)
        removeServiceMapping(did.uri)
        if (hasDid(did.uri)) {
            WaltIdDidService.deleteDid(did.uri)
            keyStore.getKeyId(did.uri)?.also { keyStore.delete(it) }
        }
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
        return toNessusDidDoc(waltDidDoc)
    }

    fun loadOrResolveDid(uri: String): Did? {
        return when {
            hasDid(uri) -> loadDid(uri)
            else -> resolveDid(uri)
        }
    }

    fun loadOrResolveDidDoc(alias: String): DidDoc? {
        return when(keyStore.getKeyId(alias)) {
            is String -> loadDidDoc(alias)
            else -> resolveDidDoc(alias)
        }
    }

    fun resolveDid(uri: String): Did? {
        val waltDidDoc = withPlugin(didMethod(uri)).resolveDidDoc(uri)
        return waltDidDoc?.let { toNessusDid(it) }
    }

    fun resolveDidDoc(alias: String): DidDoc? {
        val uri = DidUrl.from(alias).did
        val waltDidDoc = withPlugin(didMethod(alias)).resolveDidDoc(alias)
        if (waltDidDoc != null && serviceMapping[uri] == null) {
            val endpointUrl = modelService.findWalletByDid(uri)?.endpointUrl
            val didCommServices = endpointUrl?.let {
                generateDidCommServices(uri, DidOptions(it))
            } ?: listOf()
            addServiceMapping(uri, didCommServices)
        }
        return waltDidDoc?.let { toNessusDidDoc(it) }
    }

    fun importDid(did: Did): KeyId {
        log.info { "Importing Did: ${did.encodeJson(true)}" }
        return withPlugin(did.method).importDid(did)
    }

    fun importDidDoc(didDoc: DidDoc): KeyId {
        log.info { "Importing DidDoc: ${didDoc.encodeJson(true)}" }
        val method = didMethod(didDoc.id)
        val encodedDoc = didDoc.encodeJson()
        val waltDidDoc = WaltIdDidDoc.decode(encodedDoc)
        addServiceMapping(didDoc.id, didDoc.didCommServices)
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

            val didCommServices = generateDidCommServices(did.uri, options)
            addServiceMapping(did.uri, didCommServices)

            val waltDidDoc = WaltIdDidService.resolve(did.uri)
            storeDid(waltDidDoc)

            val didDocV1 = toNessusDidDoc(waltDidDoc)
            appendKeyStoreAliases(keyId, did, didDocV1)

            return did
        }

        override fun loadDid(uri: String): Did {
            return toNessusDid(loadDidDoc(uri))
        }

        override fun loadDidDoc(uri: String): WaltIdDid {
            return WaltIdDidService.load(uri)
        }

        override fun resolveDid(uri: String): Did {
            return toNessusDid(resolveDidDoc(uri))
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
            val didDocV1 = toNessusDidDoc(didDoc)
            appendKeyStoreAliases(keyId, did, didDocV1)

            return keyId
        }

        override fun importDidDoc(didDoc: WaltIdDidDoc): KeyId {

            // Construct the Did from the DidDoc
            val did = toNessusDid(didDoc)

            // Store verification key
            WaltIdDidService.importDidAndKeys(did.uri)
            val keyId = keyStore.load(did.uri).keyId

            // Store the given DidDoc
            storeDid(didDoc)

            // Store key aliases referenced from the DidDoc
            val didDocV1 = toNessusDidDoc(didDoc)
            appendKeyStoreAliases(keyId, did, didDocV1)

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

                    val didCommServices = generateDidCommServices(did.uri, options)
                    addServiceMapping(did.uri,  didCommServices)

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
                    val service = mutableMapOf<String, Any>("type" to "DIDCommMessaging")
                    options.endpointUrl?.also { service["serviceEndpoint"] = it }
                    options.routingKeys?.also { service["routingKeys"] = it }

                    val did = didUriToDid(createPeerDIDNumalgo2(listOf(encryptionKey), listOf(signingKey), service.encodeJson()))
                    val sicpaDidDoc = SicpaDidDoc.fromJson(resolvePeerDID(did.uri))
                    addServiceMapping(did.uri, sicpaDidDoc.didCommServices)

                    val didDoc = WaltIdDidDoc.decode(fixupDidDoc(sicpaDidDoc))
                    Pair(did, didDoc)
                }

                else -> throw IllegalArgumentException("Unsupported numalgo: ${options.numalgo}")
            }

            check(isPeerDID(did.uri)) { "Not a did:peer: ${did.uri}" }
            checkNotNull(waltDidDoc) { "Cannot resolve: ${did.uri}" }

            storeDid(waltDidDoc)

            val didDocV1 = toNessusDidDoc(waltDidDoc)
            appendKeyStoreAliases(keyId, did, didDocV1)

            return did
        }

        override fun loadDid(uri: String): DidPeer {
            val did = toNessusDid(loadDidDoc(uri))
            return DidPeer(did.id, did.method, did.verkey)
        }

        override fun loadDidDoc(uri: String): WaltIdDidDoc {
            return WaltIdDidService.load(uri)
        }

        override fun resolveDid(uri: String): Did? {
            return resolveDidDoc(uri)?.let { toNessusDid(it) }
        }

        override fun resolveDidDoc(uri: String): WaltIdDidDoc? {
            val sicpaDidDoc = SicpaDidDoc.fromJson(resolvePeerDID(uri))
            if (getServiceEndpoint(sicpaDidDoc) != null)
                addServiceMapping(uri, sicpaDidDoc.didCommServices)
            val peerDidDoc = fixupDidDoc(sicpaDidDoc)
            return WaltIdDidDoc.decode(peerDidDoc)
        }

        override fun importDid(did: Did): KeyId {

            // Store verification key
            val keyId = keyStore.getKeyId(did.uri)?.let { KeyId(it) } ?: run {
                val pubkeyBytes = did.verkey.decodeBase58()
                storePubkeyBytes(pubkeyBytes)
            }

            val sicpaDidDoc = SicpaDidDoc.fromJson(resolvePeerDID(did.uri))
            if (getServiceEndpoint(sicpaDidDoc) != null)
                addServiceMapping(did.uri, sicpaDidDoc.didCommServices)

            // Generate WaltIdDidDoc
            val didDoc =  WaltIdDidDoc.decode(sicpaDidDoc.encodeJson())

            // Store the generated DidDoc
            storeDid(didDoc!!)

            // Store key aliases referenced from the DidDoc
            val didDocV1 = toNessusDidDoc(didDoc)
            appendKeyStoreAliases(keyId, did, didDocV1)

            return keyId
        }

        override fun importDidDoc(didDoc: WaltIdDidDoc): KeyId {

            // Construct the Did from the DidDoc
            val did = toNessusDid(didDoc)

            // Store verification key
            val keyId = keyStore.getKeyId(did.uri)?.let { KeyId(it) } ?: run {
                val pubkeyBytes = did.verkey.decodeBase58()
                storePubkeyBytes(pubkeyBytes)
            }

            // Store the given DidDoc
            storeDid(didDoc)

            // Store key aliases referenced from the DidDoc
            val didDocV1 = toNessusDidDoc(didDoc)
            appendKeyStoreAliases(keyId, did, didDocV1)

            return keyId
        }

        // Did Document @context not optional in WaltId
        // https://github.com/walt-id/waltid-ssikit/issues/251
        private fun fixupDidDoc(didDoc: SicpaDidDoc): String {
            val decoded = didDoc.encodeJson().decodeJson().toMutableMap()
            if ("@context" !in decoded) {
                decoded["@context"] = DID_CONTEXT_URL
            }
            return decoded.encodeJson()
        }

        private fun getServiceEndpoint(didDoc: SicpaDidDoc) =
            didDoc.didCommServices.map { it.serviceEndpoint }.firstOrNull()
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

            val didCommServices = generateDidCommServices(did.uri, options)
            addServiceMapping(did.uri, didCommServices)

            val waltDidDoc = generateWaltIdDidDoc(did, pubkeyBytes)
            storeDid(waltDidDoc)

            val didDocV1 = toNessusDidDoc(waltDidDoc)
            appendKeyStoreAliases(keyId, did, didDocV1)

            return did
        }

        override fun loadDid(uri: String): Did {
            return toNessusDid(loadDidDoc(uri))
        }

        override fun loadDidDoc(uri: String): WaltIdDid {
            return WaltIdDidService.load(uri)
        }

        override fun resolveDid(uri: String): Did? {
            return resolveDidDoc(uri)?.let { toNessusDid(it) }
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
            val didDocV1 = toNessusDidDoc(didDoc)
            appendKeyStoreAliases(keyId, did, didDocV1)

            return keyId
        }

        override fun importDidDoc(didDoc: WaltIdDidDoc): KeyId {

            // Construct the Did from the DidDoc
            val did = toNessusDid(didDoc)

            // Store verification key
            val keyId = keyStore.getKeyId(did.uri)?.let { KeyId(it) } ?: run {
                val pubkeyBytes = did.verkey.decodeBase58()
                storePubkeyBytes(pubkeyBytes)
            }

            // Store the given DidDoc
            storeDid(didDoc)

            // Store key aliases referenced from the DidDoc
            val didDocV1 = toNessusDidDoc(didDoc)
            appendKeyStoreAliases(keyId, did, didDocV1)

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

        keyStore.addAlias(keyId, did.uri)
        keyStore.addAlias(keyId, did.verkey)

        didDoc.verificationMethods.forEach { vm -> keyStore.addAlias(keyId, vm.id) }
    }

    private fun generateDidCommServices(uri: String, options: DidOptions?): List<DIDCommService> {
        val didCommServices = mutableListOf<DIDCommService>()
        options?.also {
            val endpointUrl = options.endpointUrl
            checkNotNull(endpointUrl) { "No endpointUrl in: $options" }
            didCommServices.add(DIDCommService(
                id = uri,
                serviceEndpoint = endpointUrl,
                routingKeys = options.routingKeys ?: listOf(),
                accept = options.accept ?: DEFAULT_ACCEPT,
            ))
        }
        return didCommServices
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

    private fun addServiceMapping(uri: String, services: List<DIDCommService>) {
        if (uri in serviceMapping) {
            val existing = serviceMapping[uri]
            if (existing != services) {
                log.warn { "Update service mapping: $existing => $services" }
                serviceMapping[uri] = services
            }
        } else {
            log.debug { "Add service mapping: $uri => $services" }
            serviceMapping[uri] = services
        }
    }

    private fun removeServiceMapping(uri: String) {
        val services = serviceMapping.remove(uri)
        log.debug { "Removed service mapping: $uri => $services" }
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

    private fun toNessusDid(didDoc: WaltIdDidDoc): Did {
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

    private fun toNessusDidDoc(docDoc: WaltIdDidDoc): DidDoc {

        val verificationMethods = mutableListOf<WaltIdVerificationMethod>()
        docDoc.verificationMethod?.also { verificationMethods.addAll(it) }

        fun visitVerificationMethod(vm: WaltIdVerificationMethod): String {
            if (!vm.isReference)
                verificationMethods.add(vm)
            return vm.id
        }

        // All plugins are supposed to store the DIDCommService at create/import time
        val didCommServices = serviceMapping[docDoc.id]
        checkNotNull(didCommServices) { "No services for ${docDoc.id}, we have: ${serviceMapping.keys}" }

        return DidDoc(
            docDoc.id,
            context = docDoc.context?.let { docDoc.context } ?: listOf(),
            alsoKnownAs = listOf(),
            controller = listOf(),
            authentications = docDoc.authentication?.map { visitVerificationMethod(it) } ?: listOf(),
            assertionMethods = docDoc.assertionMethod?.map { visitVerificationMethod(it) } ?: listOf(),
            keyAgreements = docDoc.keyAgreement?.map { visitVerificationMethod(it) } ?: listOf(),
            capabilityInvocations = docDoc.capabilityInvocation?.map { visitVerificationMethod(it) } ?: listOf(),
            capabilityDelegations = docDoc.capabilityDelegation?.map { visitVerificationMethod(it) } ?: listOf(),
            verificationMethods = verificationMethods.map { it.toVerificationMethod() },
            didCommServices = didCommServices)
    }

    private fun withPlugin(method: DidMethod): DidServicePlugin {
        return when(method) {
            DidMethod.KEY -> DidKeyPlugin
            DidMethod.PEER -> DidPeerPlugin
            DidMethod.SOV -> DidSovPlugin
        }
    }
}

