package org.nessus.didcomm.test.model

import mu.KotlinLogging
import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.hyperledger.acy_py.generated.model.InvitationRecord
import org.junit.jupiter.api.Test
import org.nessus.didcomm.model.MessageReader
import org.nessus.didcomm.model.MessageWriter
import org.nessus.didcomm.model.OutOfBandInvitation
import kotlin.test.assertEquals

class OutOfBandInvitationTest {

    private val log = KotlinLogging.logger {}

    @Test
    fun testOutOfBandInvitation() {

        val exp: Message = OutOfBand.FABER_OUT_OF_BAND_INVITATION
        val expBody = OutOfBandInvitation.fromBody(exp.body)
        val expJson: String = MessageWriter.toJson(exp)
        log.info("exp: {}", expJson)

        val was = MessageReader.fromJson(expJson)
        log.info("was: {}", MessageWriter.toJson(was))
        assertEquals(exp, was)

        val wasBody = OutOfBandInvitation.fromBody(was.body)
        log.info("body: {}", MessageWriter.toJson(wasBody))
        assertEquals(expBody, wasBody)
    }

    @Test
    fun testOutOfBandEncoding() {
        val exp: Message = OutOfBand.ALICE_OUT_OF_BAND_INVITATION
        val expJson: String = MessageWriter.toJson(exp)
        log.info("exp: {}", expJson)

        val base64URLEncoded = MessageWriter.toBase64URL(exp)
        log.info("enc: {}", base64URLEncoded)
        assertEquals("eyJpZCI6IjY5MjEy", base64URLEncoded.substring(0, 16))
    }

    @Test
    fun testWrappedOutOfBandInvitation() {

        val exp: Message = OutOfBand.FABER_OUT_OF_BAND_INVITATION_WRAPPED
        val expJson: String = MessageWriter.toJson(exp)
        log.info("exp: {}", expJson)

        val att0: Attachment = exp.attachments?.get(0)!!
        val invJson = MessageWriter.toJson(att0.data.toJSONObject()["json"]!!)
        val invRec: InvitationRecord = MessageReader.fromJson(invJson, InvitationRecord::class.java)
        assertEquals(att0.id, invRec.inviMsgId)
    }
}
