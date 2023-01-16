package org.nessus.didcomm.service

import id.walt.crypto.Key
import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.KeyId
import id.walt.crypto.convertRawKeyToMultiBase58Btc
import id.walt.crypto.decodeRawPubKeyBase64
import id.walt.crypto.getMulticodecKeyCode
import id.walt.crypto.newKeyId
import id.walt.servicematrix.ServiceProvider
import id.walt.services.CryptoProvider
import id.walt.services.crypto.CryptoService
import id.walt.services.keystore.KeyStoreService
import id.walt.services.keystore.KeyType
import org.nessus.didcomm.crypto.NessusCryptoService
import org.nessus.didcomm.crypto.convertEd25519toRaw
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.util.decodeBase58
import org.nessus.didcomm.util.encodeBase58
import org.nessus.didcomm.util.encodeBase64
import org.nessus.didcomm.wallet.DidMethod
import java.security.KeyFactory
import java.security.KeyPair


val DEFAULT_KEY_ALGORITHM = KeyAlgorithm.EdDSA_Ed25519

class DidService: NessusBaseService() {
    override val implementation get() = serviceImplementation<DidService>()

    companion object: ServiceProvider {
        private val implementation = DidService()
        override fun getService() = implementation
    }

    fun createDid(method: DidMethod, algorithm: KeyAlgorithm? = null, seed: ByteArray? = null): Did {
        require(method == DidMethod.KEY) { "Method not supported: $method" }

        val cryptoService = CryptoService.getService().implementation as NessusCryptoService
        val keyAlgorithm = algorithm ?: DEFAULT_KEY_ALGORITHM
        val keyId = cryptoService.generateKey(keyAlgorithm, seed)

        val keyStore = KeyStoreService.getService()
        val key = keyStore.load(keyId.id, KeyType.PUBLIC)

        val pubKeyRaw = key.getPublicKey().convertEd25519toRaw()
        val id = convertRawKeyToMultiBase58Btc(pubKeyRaw, getMulticodecKeyCode(keyAlgorithm))
        val verkey = pubKeyRaw.encodeBase58()

        // Add verkey and did as alias
        val did = Did(id, method, keyAlgorithm, verkey)
        keyStore.addAlias(keyId, did.qualified)
        keyStore.addAlias(keyId, did.verkey)

        return did
    }

    fun registerVerkey(did: Did): KeyId {
        check(did.algorithm == KeyAlgorithm.EdDSA_Ed25519) { "Unsupported key algorithm: $did" }
        val algorithm = did.algorithm
        val rawBytes = did.verkey.decodeBase58()
        val keyFactory = KeyFactory.getInstance("Ed25519")
        val publicKey = decodeRawPubKeyBase64(rawBytes.encodeBase64(), keyFactory)
        val key = Key(newKeyId(), algorithm, CryptoProvider.SUN, KeyPair(publicKey, null))
        val keyId = key.keyId

        val keyStore = KeyStoreService.getService()
        keyStore.store(key)

        // Add verkey and did as alias
        keyStore.addAlias(keyId, did.qualified)
        keyStore.addAlias(keyId, did.verkey)

        // Verify stored public key bytes
        val storedKey = keyStore.load(did.verkey, KeyType.PUBLIC)
        check(did.verkey == storedKey.getPublicKey().convertEd25519toRaw().encodeBase58())

        return keyId
    }
}