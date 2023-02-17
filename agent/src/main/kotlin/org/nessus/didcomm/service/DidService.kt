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

import com.goterl.lazysodium.interfaces.Sign
import com.nimbusds.jose.jwk.Curve
import com.nimbusds.jose.jwk.OctetKeyPair
import id.walt.crypto.Key
import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.KeyId
import id.walt.crypto.convertRawKeyToMultiBase58Btc
import id.walt.crypto.decodeRawPubKeyBase64
import id.walt.crypto.getMulticodecKeyCode
import id.walt.crypto.newKeyId
import id.walt.model.DidUrl
import id.walt.servicematrix.ServiceProvider
import id.walt.services.CryptoProvider
import id.walt.services.crypto.CryptoService
import id.walt.services.key.Keys
import id.walt.services.keystore.KeyStoreService
import id.walt.services.keystore.KeyType
import mu.KotlinLogging
import org.nessus.didcomm.crypto.LazySodiumService
import org.nessus.didcomm.crypto.LazySodiumService.convertEd25519toCurve25519
import org.nessus.didcomm.crypto.LazySodiumService.convertEd25519toRaw
import org.nessus.didcomm.crypto.NessusCryptoService
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.util.decodeBase58
import org.nessus.didcomm.util.encodeBase58
import org.nessus.didcomm.util.encodeBase64
import org.nessus.didcomm.util.encodeBase64Url
import org.nessus.didcomm.util.trimJson
import java.security.KeyFactory
import java.security.KeyPair


val DEFAULT_KEY_ALGORITHM = KeyAlgorithm.EdDSA_Ed25519

fun Did.toOctetKeyPair(): OctetKeyPair {
    val keyStore = KeyStoreService.getService()
    return keyStore.load(qualified, KeyType.PRIVATE).toOctetKeyPair()
}

fun Key.toOctetKeyPair(): OctetKeyPair {
    check(keyPair != null) { "No keyPair" }
    return Keys(keyId.id, keyPair!!, "SunEC").toOctetKeyPair()
}

typealias WaltIdDidService = id.walt.services.did.DidService
typealias WaltIdDidMethod = id.walt.model.DidMethod
typealias WaltIdDidDoc = id.walt.model.Did

class DidService: NessusBaseService() {
    override val implementation get() = serviceImplementation<DidService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = DidService()
        override fun getService() = implementation
    }

    private val cryptoService get() = CryptoService.getService().implementation as NessusCryptoService
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
        // TODO: This should be the other way around i.e. Did.fromSpec delegating to here
        return Did.fromSpec(loadDidDocument(did).id)
    }

    fun loadDidDocument(did: String): DidDoc {
        return DidDoc(WaltIdDidService.load(did))
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

    fun toOctetKeyPair(kid: String, crv: Curve, keyType: KeyType = KeyType.PUBLIC): OctetKeyPair {

        val key: Key = keyStore.load(kid, keyType)
        check(key.cryptoProvider == CryptoProvider.SUN) { "Unexpected provider: ${key.cryptoProvider}" }
        check(key.algorithm == KeyAlgorithm.EdDSA_Ed25519) { "Unexpected algorithm: ${key.algorithm}" }

        return when(crv) {

            Curve.Ed25519 -> {
                when(keyType) {

                    KeyType.PRIVATE -> {
                        key.toOctetKeyPair()
                    }

                    KeyType.PUBLIC -> {
                        val ed25519PubBytes = key.getPublicKeyBytes()
                        OctetKeyPair.parse("""
                        {
                            "kty": "OKP",
                            "crv": "Ed25519",
                            "x": "${ed25519PubBytes.encodeBase64Url()}"
                        }                
                        """.trimJson())
                    }
                }
            }

            Curve.X25519 -> {
                when(keyType) {

                    KeyType.PRIVATE -> {
                        val keys = Keys(key.keyId.id, key.keyPair!!, "SunEC")
                        val ed25519PubBytes = keys.getPubKey()
                        val ed25519PrvBytes = keys.getPrivKey()

                        val ed25519KeyPair = com.goterl.lazysodium.utils.KeyPair(
                            com.goterl.lazysodium.utils.Key.fromBytes(ed25519PubBytes),
                            com.goterl.lazysodium.utils.Key.fromBytes(ed25519PrvBytes)
                        )

                        val lazySign = LazySodiumService.lazySodium as Sign.Lazy
                        val x25519KeyPair = lazySign.convertKeyPairEd25519ToCurve25519(ed25519KeyPair)
                        val x25519PubBytes = x25519KeyPair.publicKey.asBytes
                        val x25519PrvBytes = x25519KeyPair.secretKey.asBytes

                        OctetKeyPair.parse("""
                        {
                            "kty": "OKP",
                            "crv": "X25519",
                            "x": "${x25519PubBytes.encodeBase64Url()}",
                            "d": "${x25519PrvBytes.encodeBase64Url()}"
                        }                
                        """.trimJson())
                    }

                    KeyType.PUBLIC -> {
                        val ed25519PubBytes = key.getPublicKeyBytes()
                        val x25519PubBytes = ed25519PubBytes.convertEd25519toCurve25519().asBytes
                        OctetKeyPair.parse("""
                        {
                            "kty": "OKP",
                            "crv": "X25519",
                            "x": "${x25519PubBytes.encodeBase64Url()}"
                        }                
                        """.trimJson())
                    }
                }
            }

            else -> throw IllegalArgumentException("Unsupported curve: $crv")
        }
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

class DidDoc internal constructor(didDoc: WaltIdDidDoc) {
    private val _delegate = didDoc

    val context = didDoc.context
    val id = didDoc.id
    val verificationMethod = didDoc.verificationMethod
    val authentication = didDoc.authentication
    val assertionMethod = didDoc.assertionMethod
    val capabilityDelegation = didDoc.capabilityDelegation
    val capabilityInvocation = didDoc.capabilityInvocation
    val keyAgreement = didDoc.keyAgreement
    val serviceEndpoint = didDoc.serviceEndpoint

    companion object {
        fun decode(didDoc: String): DidDoc? {
            val waltDid = WaltIdDidDoc.decode(didDoc)
            return waltDid?.run { DidDoc(this) }
        }
    }

    val url: DidUrl
        get() = DidUrl.from(id)

    val method: DidMethod
        get() = DidMethod.fromValue(url.method)

    fun encode() = _delegate.encode()
    fun encodePretty() = _delegate.encodePretty()
}