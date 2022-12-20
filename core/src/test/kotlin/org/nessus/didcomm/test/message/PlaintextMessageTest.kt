package org.nessus.didcomm.test.message

import org.didcommx.didcomm.DIDComm
import org.didcommx.didcomm.message.Message
import org.didcommx.didcomm.model.PackPlaintextParams
import org.didcommx.didcomm.model.UnpackParams
import org.didcommx.didcomm.test.fixtures.JWM.Companion.ALICE_DID
import org.didcommx.didcomm.test.fixtures.JWM.Companion.BOB_DID
import org.didcommx.didcomm.test.mock.AliceSecretResolverMock
import org.didcommx.didcomm.test.mock.DIDDocResolverMock
import org.junit.jupiter.api.Assertions
import org.junit.jupiter.api.Test


class PlaintextMessageTest {

    @Test
    fun testPlaintextPackUnpack() {
        val didComm = DIDComm(DIDDocResolverMock(), AliceSecretResolverMock())

        // ALICE
        val message = Message.builder(
            id = "1234567890",
            body = mapOf("messagespecificattribute" to "and its value"),
            type = "http://example.com/protocols/lets_do_lunch/1.0/proposal"
        )
            .from(ALICE_DID)
            .to(listOf(BOB_DID))
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .build()
        val packResult = didComm.packPlaintext(
            PackPlaintextParams.builder(message)
                .build()
        )
        val packedMessage = packResult.packedMessage
        // println("Send $packedMessage")

        // BOB
        val unpackResult = didComm.unpack(
            UnpackParams.Builder(packResult.packedMessage).build()
        )
        val unpackedMessage = unpackResult.message
        // println("Recv $unpackedMessage")

        Assertions.assertEquals(packedMessage, unpackedMessage.toString())
    }
}
