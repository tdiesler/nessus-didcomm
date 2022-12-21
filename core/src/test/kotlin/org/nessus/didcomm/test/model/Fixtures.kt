package org.nessus.didcomm.test.model

import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import org.nessus.didcomm.model.OutOfBandInvitationV2

class OutOfBand {

    companion object {

        const val ALICE_DID = "did:example:alice"
        const val FABER_DID = "did:example:faber"

        private const val ID = "1234567890"
        private const val TYPE = OutOfBandInvitationV2.type

        val OUT_OF_BAND_INVITATION = Message.builder(ID, mapOf(
            "goal_code" to "issue-vc",
            "goal" to "To issue a Faber College Graduate credential",
            "accept" to listOf("didcomm/v2", "didcomm/aip2;env=rfc587")),
            TYPE)
            .from(FABER_DID)
            .createdTime(1516269022)
            .expiresTime(1516385931)
            .attachments(listOf(
                Attachment.builder(
                    "request-0", Attachment.Data.parse(mapOf("base64" to "qwerty"))).build()))
            .build()
   }
}
