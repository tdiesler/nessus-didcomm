package org.nessus.didcomm.service

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
        return when (keyStore.getKeyId(kid)) {
            null -> {
                Optional.ofNullable(null)
            }
            else -> {
                val crv = when {
                    kid.contains("#key-x25519-") -> CurveType.X25519
                    else -> CurveType.Ed25519
                }
                val okp = didService.toOctetKeyPair(kid, crv, KeyType.PRIVATE)
                Optional.of(Secret(
                    kid = kid,
                    type = VerificationMethodType.JSON_WEB_KEY_2020,
                    verificationMaterial = VerificationMaterial(
                        VerificationMaterialFormat.JWK,
                        okp.toJSONString()
                    ))
                )
            }
        }
    }

    override fun findKeys(kids: List<String>): Set<String> {
        return kids
            .filter { keyStore.getKeyId(it) != null }
            .filter { keyStore.load(it).keyPair != null }
            .toSet()
    }
}