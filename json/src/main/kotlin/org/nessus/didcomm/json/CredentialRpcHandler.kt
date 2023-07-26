/*-
 * #%L
 * Nessus DIDComm :: ITests
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
package org.nessus.didcomm.json

import kotlinx.serialization.json.Json
import org.nessus.didcomm.json.model.VCData
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.W3CVerifiableCredential
import org.nessus.didcomm.service.ISSUE_CREDENTIAL_PROTOCOL_V3

object CredentialRpcHandler: AbstractRpcHandler() {

    fun issueCredential(payload: String): W3CVerifiableCredential {
        val data = Json.decodeFromString<VCData>(payload)
        checkNotNull(data.issuerId) { "No issuerId" }
        checkNotNull(data.holderDid) { "No holderDid" }
        checkNotNull(data.template) { "No template" }
        checkNotNull(data.subjectData) { "No subjectData" }
        val issuer = assertWallet(data.issuerId)
        val issuerHolderCon = issuer.connections.firstOrNull { ic -> ic.theirDid.uri == data.holderDid }
        checkNotNull(issuerHolderCon) { "Issuer ${issuer.name} has not connection to ${data.holderDid}" }
        val holderDid = issuerHolderCon.theirDid
        MessageExchange()
            .withConnection(issuerHolderCon)
            .withProtocol(ISSUE_CREDENTIAL_PROTOCOL_V3)
            .sendCredentialOffer(
                issuer = issuer,
                holderDid = holderDid,
                template = data.template,
                subjectData = data.subjectData
            )
            .awaitCredentialRequest(issuer, holderDid)
            .awaitCredentialAck(issuer, holderDid)

        val vc = issuer.findVerifiableCredentialsByType(data.template)
            .firstOrNull { "${it.credentialSubject?.id}" == holderDid.uri }
        checkNotNull(vc) { "Issuer ${issuer.name} has no ${data.template} credential for subject: ${holderDid.uri}" }
        return vc
    }
}
