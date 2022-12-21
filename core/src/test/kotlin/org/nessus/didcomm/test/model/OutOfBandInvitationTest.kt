package org.nessus.didcomm.test.model

import mu.KotlinLogging
import org.didcommx.didcomm.message.Message
import org.junit.jupiter.api.Test
import org.nessus.didcomm.model.MessageParser
import org.nessus.didcomm.model.MessageWriter
import org.nessus.didcomm.model.OutOfBandInvitationV2
import kotlin.test.Ignore
import kotlin.test.assertEquals

@Ignore
class OutOfBandInvitationTest {

    private val log = KotlinLogging.logger {}

    @Test
    fun testOutOfBandInvitation() {

        val exp: Message = OutOfBand.OUT_OF_BAND_INVITATION
        val expBody = OutOfBandInvitationV2.fromBody(exp.body)
        val expJson: String = MessageWriter.toJson(exp)
        log.info("exp: {}", expJson)

        val was = MessageParser.fromJson(expJson)
        log.info("was: {}", MessageWriter.toJson(was))
        assertEquals(exp, was)

        val wasBody = OutOfBandInvitationV2.fromBody(was.body)
        log.info("body: {}", MessageWriter.toJson(wasBody))
        assertEquals(expBody, wasBody)
    }

}
