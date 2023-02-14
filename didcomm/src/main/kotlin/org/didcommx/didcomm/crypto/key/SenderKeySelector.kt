package org.didcommx.didcomm.crypto.key

import com.nimbusds.jose.jwk.Curve
import org.didcommx.didcomm.diddoc.DIDDoc
import org.didcommx.didcomm.diddoc.DIDDocResolver
import org.didcommx.didcomm.exceptions.DIDDocException
import org.didcommx.didcomm.exceptions.DIDDocNotResolvedException
import org.didcommx.didcomm.exceptions.IncompatibleCryptoException
import org.didcommx.didcomm.exceptions.SecretNotFoundException
import org.didcommx.didcomm.secret.SecretResolver
import org.didcommx.didcomm.utils.divideDIDFragment
import org.didcommx.didcomm.utils.isDIDFragment

class SenderKeySelector(private val didDocResolver: DIDDocResolver, private val secretResolver: SecretResolver) {
    fun findSigningKey(signFrom: String): Key = Key.fromSecret(
        if (isDIDFragment(signFrom)) {
            secretResolver.findKey(signFrom).orElseThrow { throw SecretNotFoundException(signFrom) }
        } else {
            val didDoc = didDocResolver.resolve(signFrom).orElseThrow { throw DIDDocNotResolvedException(signFrom) }

            val authentication = didDoc.authentications.firstOrNull()
                ?: throw DIDDocException("The DID Doc '${didDoc.did}' does not contain compatible 'authentication' verification methods")

            secretResolver.findKey(authentication).orElseThrow { throw SecretNotFoundException(signFrom) }
        }
    )

    fun findAuthCryptKeys(from: String, to: String): Pair<Key, List<Key>> {
        val (didFrom) = divideDIDFragment(from)
        val (didTo) = divideDIDFragment(to)
        val didDocTo = didDocResolver.resolve(didTo).orElseThrow { throw DIDDocNotResolvedException(didTo) }

        return if (isDIDFragment(from)) {
            val sender = secretResolver.findKey(from)
                .map { Key.fromSecret(it) }
                .orElseThrow { throw SecretNotFoundException(from) }

            val recipients = findRecipientKeys(didDocTo, to, sender.curve)
                .ifEmpty { throw IncompatibleCryptoException("The recipient '$to' curve is not compatible to '${sender.curve.name}'") }

            Pair(sender, recipients)
        } else {
            val didDocFrom = didDocResolver.resolve(didFrom).orElseThrow { throw DIDDocNotResolvedException(didFrom) }
            didDocFrom.keyAgreements
                .asSequence()
                .map { secretResolver.findKey(it) }
                .filter { it.isPresent }
                .map { it.get() }
                .map { Key.fromSecret(it) }
                .map { Pair(it, findRecipientKeys(didDocTo, to, it.curve)) }
                .firstOrNull { it.second.isNotEmpty() }
                ?: throw IncompatibleCryptoException("The DID Docs '${didDocFrom.did}' and '${didDocTo.did}' do not contain compatible 'keyAgreement' verification methods")
        }
    }

    fun findAnonCryptKeys(to: String): List<Key> {
        val (did) = divideDIDFragment(to)
        val didDoc = didDocResolver.resolve(did).orElseThrow { throw DIDDocNotResolvedException(did) }

        return if (isDIDFragment(to)) {
            val method = didDoc.findVerificationMethod(to)
            listOf(Key.fromVerificationMethod(method))
        } else {
            val selectedCurve = didDoc.keyAgreements
                .map { didDoc.findVerificationMethod(it) }
                .map { Key.fromVerificationMethod(it) }
                .map { it.curve }
                .firstOrNull()

            didDoc.keyAgreements
                .map { didDoc.findVerificationMethod(it) }
                .map { Key.fromVerificationMethod(it) }
                .filter { selectedCurve == it.curve }
                .ifEmpty { throw DIDDocException("The DID Doc '${didDoc.did}' does not contain compatible 'keyAgreement' verification methods") }
        }
    }

    private fun findRecipientKeys(didDoc: DIDDoc, to: String, curve: Curve): List<Key> {
        return if (isDIDFragment(to)) {
            val method = didDoc.findVerificationMethod(to)
            val key = Key.fromVerificationMethod(method)

            when (curve != key.curve) {
                true -> listOf()
                false -> listOf(key)
            }
        } else {
            didDoc.keyAgreements
                .map { didDoc.findVerificationMethod(it) }
                .map { Key.fromVerificationMethod(it) }
                .filter { curve == it.curve }
        }
    }
}
