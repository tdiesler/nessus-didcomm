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

import id.walt.credentials.w3c.VerifiableCredential
import kotlinx.serialization.json.Json
import org.nessus.didcomm.json.model.CredentialData
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.service.ISSUE_CREDENTIAL_PROTOCOL_V3

object CredentialRpcHandler: AbstractRpcHandler() {

    fun issueCredential(payload: String): VerifiableCredential {
        val data = Json.decodeFromString<CredentialData>(payload)
        checkNotNull(data.issuerId) { "No issuerId" }
        checkNotNull(data.holderId) { "No holderId" }
        checkNotNull(data.template) { "No template" }
        checkNotNull(data.subjectData) { "No subjectData" }
        val issuer = assertWallet(data.issuerId)
        val holder = assertWallet(data.holderId)
        val issuerHolderCon = issuer.connections.first { ic -> holder.findReverseConnection(ic) != null }
        val issuerDid = issuer.getDid(issuerHolderCon.myDid.uri)
        val holderDid = holder.getDid(issuerHolderCon.theirDid.uri)
        MessageExchange()
            .withProtocol(ISSUE_CREDENTIAL_PROTOCOL_V3)
            .sendCredentialOffer(
                issuer = issuer,
                holderDid = holderDid,
                template = data.template,
                subjectData = data.subjectData
            )
            .awaitCredentialRequest(issuer, holderDid)
            .awaitIssuedCredential(holder, issuerDid)

        return holder.findVerifiableCredentialsByType(data.template)
            .first { "${it.credentialSubject?.id}" == holderDid.uri }
    }
}
