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
package org.nessus.didcomm.service

import com.google.gson.annotations.SerializedName
import id.walt.servicematrix.ServiceProvider

class InvitationService: NessusBaseService() {
    override val implementation get() = serviceImplementation<InvitationService>()

    companion object: ServiceProvider {
        private val implementation = InvitationService()
        override fun getService() = implementation
    }

    private val invitationsStorage: MutableMap<String, Invitation> = mutableMapOf()

    fun addInvitation(inviterId: String, inv: Invitation) {
        invitationsStorage[inv.atId] = inv
    }

    fun getInvitation(invId: String): Invitation? {
        return invitationsStorage[invId]
    }

    fun removeInvitation(invId: String): Invitation? {
        return invitationsStorage.remove(invId)
    }

    // Private ---------------------------------------------------------------------------------------------------------

}

data class Invitation(
    @SerializedName("@id")
    val atId: String,
    @SerializedName("@type")
    val atType: String,
    @SerializedName("handshake_protocols")
    val handshakeProtocols: List<String>,
    @SerializedName("accept")
    val accept: List<String>,
    @SerializedName("goal_code")
    val goalCode: String,
    @SerializedName("services")
    val services: List<Service>,
) {
    data class Service(
        val id: String,
        val type: String,
        val recipientKeys: List<String>,
        val serviceEndpoint: String,
    )
}