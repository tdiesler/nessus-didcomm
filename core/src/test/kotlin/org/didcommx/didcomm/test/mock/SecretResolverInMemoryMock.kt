package org.didcommx.didcomm.test.mock

import org.didcommx.didcomm.secret.Secret
import org.didcommx.didcomm.secret.SecretResolver

interface SecretResolverInMemoryMock : SecretResolver {
    fun getSecrets(): List<Secret>

    fun getSecretKids(): List<String>
}
