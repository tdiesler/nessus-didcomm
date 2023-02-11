package org.nessus.didcomm.service

import com.nimbusds.jose.jwk.Curve
import id.walt.servicematrix.ServiceProvider
import id.walt.services.keystore.KeyStoreService
import id.walt.services.keystore.KeyType
import mu.KotlinLogging
import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.secret.Secret
import org.didcommx.didcomm.secret.SecretResolver
import java.util.Optional

class SecretResolverService: NessusBaseService(), SecretResolver {
    override val implementation get() = serviceImplementation<DidService>()
    override val log = KotlinLogging.logger {}

    companion object: ServiceProvider {
        private val implementation = SecretResolverService()
        override fun getService() = implementation
    }

    private val didService get() = DidService.getService()
    private val keyStore get() = KeyStoreService.getService()

    override fun findKey(kid: String): Optional<Secret> {

        if (!hasPrivateKey(kid))
            return Optional.ofNullable(null)

        val crv = when {
            kid.contains("#key-x25519-") -> Curve.X25519
            else -> Curve.Ed25519
        }

        val okp = didService.toOctetKeyPair(kid, crv, KeyType.PRIVATE)

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