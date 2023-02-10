package org.nessus.didcomm.test.protocol.mock

import org.didcommx.didcomm.common.VerificationMaterial
import org.didcommx.didcomm.common.VerificationMaterialFormat
import org.didcommx.didcomm.common.VerificationMethodType
import org.didcommx.didcomm.secret.Secret
import org.didcommx.didcomm.secret.SecretResolverInMemory
import org.didcommx.didcomm.test.mock.SecretResolverInMemoryMock
import org.nessus.didcomm.util.trimJson
import java.util.Optional

class AliceSecretResolverMock : SecretResolverInMemoryMock {
    private val secrets = listOf(
        Secret(
            kid = "did:example:alice#key-1",
            type = VerificationMethodType.JSON_WEB_KEY_2020,
            verificationMaterial = VerificationMaterial(
                VerificationMaterialFormat.JWK,
                """
                {
                   "kty":"OKP",
                   "d":"pFRUKkyzx4kHdJtFSnlPA9WzqkDT1HWV0xZ5OYZd2SY",
                   "crv":"Ed25519",
                   "x":"G-boxFB6vOZBu-wXkm-9Lh79I8nf9Z50cILaOgKKGww"
                }
                """.trimJson()
            )
        ),

        Secret(
            kid = "did:example:alice#key-x25519-1",
            type = VerificationMethodType.JSON_WEB_KEY_2020,
            verificationMaterial = VerificationMaterial(
                VerificationMaterialFormat.JWK,
                """
                {
                   "kty":"OKP",
                   "d":"r-jK2cO3taR8LQnJB1_ikLBTAnOtShJOsHXRUWT-aZA",
                   "crv":"X25519",
                   "x":"avH0O2Y4tqLAq8y9zpianr8ajii5m4F_mICrzNlatXs"
                }
                """.trimJson()
            )
        ),
    )

    private val secretResolver = SecretResolverInMemory(secrets)

    override fun getSecrets(): List<Secret> {
        return secrets
    }

    override fun getSecretKids(): List<String> {
        return secrets.map { secret -> secret.kid }
    }

    override fun findKey(kid: String): Optional<Secret> =
        secretResolver.findKey(kid)

    override fun findKeys(kids: List<String>): Set<String> =
        secretResolver.findKeys(kids)
}
