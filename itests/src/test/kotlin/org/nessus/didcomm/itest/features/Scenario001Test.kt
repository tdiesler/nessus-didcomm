package org.nessus.didcomm.itest.features

import org.hyperledger.aries.api.out_of_band.InvitationCreateRequest
import org.junit.jupiter.api.Test
import org.nessus.didcomm.itest.AbstractAriesTest

class Scenario001Test : AbstractAriesTest() {

    @Test
    fun testFaberInvitesAlice() {
        val client = adminClient()
        val invitationRequest = InvitationCreateRequest.builder()
            .alias("Faber")
            .build()
        val invitationResponse = client.outOfBandCreateInvitation(invitationRequest, null).get()
        log.info("{}", invitationResponse)
    }
}
