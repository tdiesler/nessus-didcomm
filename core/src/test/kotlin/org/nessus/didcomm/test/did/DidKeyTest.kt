package org.nessus.didcomm.test.did

import id.walt.crypto.KeyAlgorithm
import id.walt.services.crypto.TinkCryptoService
import org.junit.jupiter.api.Test
import kotlin.test.assertTrue

class DidKeyTest {

    @Test
    fun testCreateLocalDID() {

        // Wallet().createLocalDID("sov")
        // Wallet().createLocalDID("sov", seed = "000000000000000000000000Trustee1")

        val data = "some data".toByteArray()
        val tinkCryptoService = TinkCryptoService()
        val keyId = tinkCryptoService.generateKey(KeyAlgorithm.EdDSA_Ed25519)
        val sig = tinkCryptoService.sign(keyId, data)
        val res = tinkCryptoService.verify(keyId, sig, data)
        assertTrue(res)
    }
}
