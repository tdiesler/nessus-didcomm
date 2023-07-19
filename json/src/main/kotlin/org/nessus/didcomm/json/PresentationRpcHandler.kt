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

import id.walt.credentials.w3c.VerifiablePresentation
import kotlinx.serialization.json.Json
import org.nessus.didcomm.json.model.VPData
import org.nessus.didcomm.model.MessageExchange
import org.nessus.didcomm.model.W3CVerifiableCredentialHelper
import org.nessus.didcomm.service.PRESENT_PROOF_PROTOCOL_V3
import org.nessus.didcomm.util.encodeJson

object PresentationRpcHandler: AbstractRpcHandler() {

    fun requestPresentation(payload: String): VerifiablePresentation {
        val data = Json.decodeFromString<VPData>(payload)
        checkNotNull(data.verifierId) { "No verifierId" }
        checkNotNull(data.proverDid) { "No proverDid" }
        checkNotNull(data.template) { "No template" }
        val verifier = assertWallet(data.verifierId)
        val verifierProverCon = verifier.connections.firstOrNull { ic -> ic.theirDid.uri == data.proverDid }
        checkNotNull(verifierProverCon) { "Issuer ${verifier.name} has not connection to ${data.proverDid}" }
        val verifierDid = verifierProverCon.myDid
        val proverDid = verifierProverCon.theirDid
        val prover = modelService.findWalletByDid(proverDid.uri)

        val unsignedVc = W3CVerifiableCredentialHelper.fromTemplate(
            pathOrName = data.template,
            stripValues = true)
        val unsignedVp = VerifiablePresentation.fromVerifiableCredential(unsignedVc)

        val policies = data.policies?.map {
            val params = it.params.encodeJson()
            policyService.getPolicyWithJsonArg(it.name, params)
        }

        val mex = MessageExchange()
            .withProtocol(PRESENT_PROOF_PROTOCOL_V3)
            .sendPresentationRequest(
                verifier = verifier,
                proverDid = proverDid,
                vp = unsignedVp,
                options = data.options
            )
            .awaitPresentation(verifier, proverDid)
            .also { ptcl ->
                if (policies != null) {
                    ptcl.verifyPresentation(verifier, policies)
                }
                if (prover != null)
                    ptcl.awaitPresentationAck(prover, verifierDid)
            }
            .getMessageExchange()

        modelService.findWalletByDid(proverDid.uri)?.also {
            mex.withProtocol(PRESENT_PROOF_PROTOCOL_V3)
        }
        val vp = verifier.findVerifiablePresentationsByType(data.template)
            .firstOrNull { vp -> vp.subjectId == proverDid.uri }
        checkNotNull(vp) { "Verifier ${verifier.name} has no ${data.template} presentation from subject: ${proverDid.uri}" }
        return vp
    }
}
