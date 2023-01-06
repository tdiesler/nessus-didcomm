package org.nessus.didcomm.did

import id.walt.crypto.KeyAlgorithm
import id.walt.crypto.convertRawKeyToMultiBase58Btc
import id.walt.crypto.encodeBase58
import id.walt.crypto.getMulticodecKeyCode
import id.walt.services.keystore.KeyStoreService
import id.walt.services.keystore.KeyType
import org.nessus.didcomm.crypto.NessusCryptoService
import org.nessus.didcomm.wallet.DidMethod
import org.web3j.utils.Numeric
import java.security.PrivateKey

fun ByteArray.toHex() = Numeric.toHexString(this).substring(2)

object DidService {

    val DEFAULT_KEY_ALGORITHM = KeyAlgorithm.EdDSA_Ed25519

    fun createDid(method: DidMethod, algorithm: KeyAlgorithm? = null, seed: ByteArray? = null): Did {
        require(method == DidMethod.KEY) { "Method not supported: $method" }

        // [TODO] CryptoService.getService() as NessusCryptoService
        // https://github.com/walt-id/waltid-ssikit/issues/204
        // val cryptoService = CryptoService.getService() as NessusCryptoService

        val cryptoService = NessusCryptoService()
        val keyAlgorithm = algorithm ?: DEFAULT_KEY_ALGORITHM
        val keyId = cryptoService.generateKey(keyAlgorithm, seed)

        val keyStore = KeyStoreService.getService()
        val key = keyStore.load(keyId.id, KeyType.PRIVATE)
        val prvKey = key.keyPair?.private as PrivateKey
        val pubKey = key.getPublicKey()

        val pubKeyX509 = pubKey.encoded
        check("X.509" == pubKey.format)

        // Assume that the last 32 bytes are equal to the pubkey raw bytes
        val pubKeyRaw = pubKeyX509.sliceArray(pubKeyX509.size - 32 until pubKeyX509.size)
        val id = convertRawKeyToMultiBase58Btc(pubKeyRaw, getMulticodecKeyCode(keyAlgorithm))
        val verkey = pubKeyRaw.encodeBase58()

        // Add NaCl verkey and did as alias
        val did = Did(id, method, keyAlgorithm, verkey)
        keyStore.addAlias(keyId, did.qualified)
        keyStore.addAlias(keyId, verkey)

        return did
    }
}