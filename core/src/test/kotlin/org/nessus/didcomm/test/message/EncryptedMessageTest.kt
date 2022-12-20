package org.nessus.didcomm.test.message

import com.nimbusds.jose.util.JSONObjectUtils
import org.didcommx.didcomm.DIDComm
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.test.fixtures.JWE
import org.didcommx.didcomm.test.fixtures.JWM
import org.didcommx.didcomm.test.mock.BobSecretResolverMock
import org.didcommx.didcomm.test.mock.DIDDocResolverMock
import org.junit.jupiter.api.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals


class EncryptedMessageTest {

    @Test
    fun testEncryptedPackUnpack() {
        for (test in JWE.TEST_VECTORS) {
            val didComm = DIDComm(DIDDocResolverMock(), BobSecretResolverMock())

            val unpacked = didComm.unpack(
                UnpackParams.Builder(test.message)
                    .expectDecryptByAllKeys(true)
                    .build()
            )

            assertEquals(
                JSONObjectUtils.toJSONString(JWM.PLAINTEXT_MESSAGE.toJSONObject()),
                JSONObjectUtils.toJSONString(unpacked.message.toJSONObject())
            )

            with(unpacked.metadata) {
                assertEquals(test.expectedMetadata.encrypted, encrypted)
                assertEquals(test.expectedMetadata.authenticated, authenticated)
                assertEquals(test.expectedMetadata.anonymousSender, anonymousSender)
                assertEquals(test.expectedMetadata.nonRepudiation, nonRepudiation)

                assertEquals(test.expectedMetadata.encAlgAnon, encAlgAnon)
                assertEquals(test.expectedMetadata.encAlgAuth, encAlgAuth)

                assertEquals(test.expectedMetadata.encryptedFrom, encryptedFrom)
                assertContentEquals(test.expectedMetadata.encryptedTo, encryptedTo)

                assertEquals(test.expectedMetadata.signAlg, signAlg)
                assertEquals(test.expectedMetadata.signFrom, signFrom)

                val expectedSignedMessage = test.expectedMetadata.signedMessage?.let { true } ?: false
                val actualSignedMessage = signedMessage?.let { true } ?: false
                assertEquals(expectedSignedMessage, actualSignedMessage)
            }
        }
    }
}
