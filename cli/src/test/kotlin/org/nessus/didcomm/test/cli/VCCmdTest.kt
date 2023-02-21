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
package org.nessus.didcomm.test.cli

import io.kotest.matchers.shouldBe
import org.nessus.didcomm.model.Wallet

class VCCmdTest: AbstractCliTest() {

    @Test
    fun listTemplates() {
        cliService.execute("vc template list").isSuccess shouldBe true
    }

    @Test
    fun listPolicies() {
        cliService.execute("vc policy list").isSuccess shouldBe true
    }

    @Test
    fun issueCredential() {

        cliService.execute("wallet create --name Faber").isSuccess shouldBe true
        cliService.execute("wallet create --name Alice").isSuccess shouldBe true
        cliService.execute("wallet create --name Acme").isSuccess shouldBe true

        val faber = modelService.findWalletByName("Faber") as Wallet
        val alice = modelService.findWalletByName("Alice") as Wallet
        val acme = modelService.findWalletByName("Acme") as Wallet

        try {

            val faberDid = faber.createDid().uri
            val aliceDid = alice.createDid().uri
            val acmeDid = acme.createDid().uri

            cliService.execute("vc issue -t VerifiableId -i $faberDid -s $aliceDid target/VerifiableId.json").isSuccess shouldBe true
            cliService.execute("vc present -h $aliceDid -v $acmeDid -c 1234 target/VerifiableId.json target/VerifiablePresentation.json").isSuccess shouldBe true

            val challengePolicy = """ChallengePolicy={"challenges":["1234"],"applyToVC":false}"""
            cliService.execute("vc verify -p SignaturePolicy -p $challengePolicy -- target/VerifiablePresentation.json").isSuccess shouldBe true

        } finally {
            modelService.removeWallet(acme.id)
            modelService.removeWallet(alice.id)
            modelService.removeWallet(faber.id)
        }
    }
}
