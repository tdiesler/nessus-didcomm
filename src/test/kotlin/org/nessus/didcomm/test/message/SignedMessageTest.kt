package org.nessus.didcomm.test.message

import com.nimbusds.jose.JWSObjectJSON
import com.nimbusds.jose.util.JSONObjectUtils
import org.didcommx.didcomm.DIDComm
import org.didcommx.didcomm.fixtures.JWM
import org.didcommx.didcomm.fixtures.JWS
import org.didcommx.didcomm.mock.AliceSecretResolverMock
import org.didcommx.didcomm.mock.DIDDocResolverMock
import org.didcommx.didcomm.model.PackSignedParams
import org.didcommx.didcomm.model.UnpackParams
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals


class SignedMessageTest {

    @Test
    fun testSignedPackUnpack() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        for (test in JWS.TEST_VECTORS) {

            val packed = didComm.packSigned(
                PackSignedParams.builder(JWM.PLAINTEXT_MESSAGE, test.from).build()
            )

            val unpacked = didComm.unpack(
                UnpackParams.Builder(packed.packedMessage).build()
            )

            val expected = JWSObjectJSON.parse(test.expected)
            val signed = JWSObjectJSON.parse(packed.packedMessage)

            assertEquals(expected.signatures.first().header.toString(), signed.signatures.first().header.toString())

            assertEquals(
                JSONObjectUtils.toJSONString(JWM.PLAINTEXT_MESSAGE.toJSONObject()),
                JSONObjectUtils.toJSONString(unpacked.message.toJSONObject())
            )

            assertEquals(false, unpacked.metadata.encrypted)
            assertEquals(true, unpacked.metadata.authenticated)
            assertEquals(true, unpacked.metadata.nonRepudiation)
            assertEquals(false, unpacked.metadata.anonymousSender)
            assertEquals(test.expectedMetadata.signFrom, unpacked.metadata.signFrom)
            assertEquals(test.expectedMetadata.signAlg, unpacked.metadata.signAlg)
        }
    }
}
