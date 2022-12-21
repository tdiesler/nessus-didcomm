package org.nessus.didcomm.wallet

import id.walt.crypto.KeyAlgorithm

val DEFAULT_KEY_ALGORITHM = KeyAlgorithm.EdDSA_Ed25519

enum class DidMethod(val mname : String) {
    KEY("key"),
    SOV("sov");

    fun supportedAlgorithms() : Set<KeyAlgorithm> {
        return setOf(KeyAlgorithm.EdDSA_Ed25519)
    }
}

//open class Did(method: DidMethod) {
//}
//
//class DidKey() : Did(DidMethod.KEY) {
//}
//
//class DidSov() : Did(DidMethod.SOV) {
//}
