/*-
 * #%L
 * Nessus DIDComm :: Core
 * %%
 * Copyright (C) 2022 Nessus
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package org.nessus.didcomm.test.model.dcv2

import org.didcommx.didcomm.message.Message
import org.junit.jupiter.api.Test
import org.nessus.didcomm.model.InvitationV2
import org.nessus.didcomm.util.decodeMessage
import kotlin.test.assertEquals

class InvitationV2Test {

    @Test
    fun testOutOfBandInvitation() {

        val exp: String = OutOfBand.FABER_OUT_OF_BAND_INVITATION
        val expMsg: Message = exp.decodeMessage()
        val inviV2: InvitationV2 = InvitationV2.fromMessage(expMsg)

        val wasMsg: Message = inviV2.toMessage()
        assertEquals(expMsg.toJSONObject(), wasMsg.toJSONObject())
    }
}
