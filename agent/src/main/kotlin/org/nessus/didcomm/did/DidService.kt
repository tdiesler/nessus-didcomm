package org.nessus.didcomm.did

import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.convertRawKeyToMultiBase58Btc
import id.walt.crypto.encodeBase58
import id.walt.crypto.getMulticodecKeyCode
import id.walt.services.crypto.CryptoService
import id.walt.services.keystore.KeyStoreService
import id.walt.services.keystore.KeyType
import org.nessus.didcomm.crypto.NessusCryptoService
import org.nessus.didcomm.crypto.convertEd25519toRaw
import org.nessus.didcomm.wallet.DidMethod

object DidService {

    val DEFAULT_KEY_ALGORITHM = KeyAlgorithm.EdDSA_Ed25519

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

        // Add NaCl verkey and did as alias
        val did = Did(id, method, keyAlgorithm, verkey)
        keyStore.addAlias(keyId, did.qualified)
        keyStore.addAlias(keyId, verkey)

        return did
    }
}