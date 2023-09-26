package org.nessus.didcomm.service

import com.nimbusds.jose.jwk.Curve
import id.walt.services.keystore.KeyStoreService
import id.walt.services.keystore.KeyType
import mu.KotlinLogging
import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.common.VerificationMethodType.ED25519_VERIFICATION_KEY_2018
import org.didcommx.didcomm.common.VerificationMethodType.ED25519_VERIFICATION_KEY_2020
import org.didcommx.didcomm.common.VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2019
import org.didcommx.didcomm.common.VerificationMethodType.X25519_KEY_AGREEMENT_KEY_2020
import org.didcommx.didcomm.secret.Secret
import org.didcommx.didcomm.secret.SecretResolver
import java.util.Optional

object SecretResolverService: ObjectService<SecretResolverService>(), SecretResolver {
    val log = KotlinLogging.logger {}

    @JvmStatic
    fun getService() = apply { }

    private val didService get() = DidService.getService()
    private val cryptoService get() = NessusCryptoService.getService()
    private val keyStore get() = KeyStoreService.getService()

    override fun findKey(kid: String): Optional<Secret> {

        if (!hasPrivateKey(kid))
            return Optional.ofNullable(null)

        val didDoc = didService.loadDidDoc(kid)
        val verificationMethod = didDoc.verificationMethods.first { it.id == kid }
        val crv = when(verificationMethod.type) {
            ED25519_VERIFICATION_KEY_2018,
            ED25519_VERIFICATION_KEY_2020 -> Curve.Ed25519
            X25519_KEY_AGREEMENT_KEY_2019,
            X25519_KEY_AGREEMENT_KEY_2020 -> Curve.X25519
            else -> {
                log.warn { "Cannot find curve for: ${verificationMethod.type}" }
                return Optional.ofNullable(null)
            }
        }

        val okp = cryptoService.toOctetKeyPair(kid, crv, KeyType.PRIVATE)

        return Optional.of(Secret(
            kid = kid,
            type = VerificationMethodType.JSON_WEB_KEY_2020,
            verificationMaterial = VerificationMaterial(
                VerificationMaterialFormat.JWK,
                okp.toJSONString()
            ))
        )
    }

    override fun findKeys(kids: List<String>): Set<String> {
        return kids.filter { hasPrivateKey(it) }.toSet()
    }

    // KeyStore.load(_, KeyType.PRIVATE) throws an Exception when there
    // is no private part. Unfortunately we cannot test for that
    private fun hasPrivateKey(kid: String): Boolean {
        return try {
            keyStore.load(kid, KeyType.PRIVATE)
            true
        } catch (e: Exception) {
            false
        }
    }
}