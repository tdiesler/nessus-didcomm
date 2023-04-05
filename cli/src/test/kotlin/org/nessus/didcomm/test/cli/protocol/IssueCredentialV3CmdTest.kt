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
package org.nessus.didcomm.test.cli.protocol

import io.kotest.matchers.shouldBe
import org.nessus.didcomm.model.Wallet
import org.nessus.didcomm.test.cli.AbstractCLITest
import org.nessus.didcomm.util.trimJson

class IssueCredentialV3CmdTest: AbstractCLITest() {

    @Test
    fun listTemplates() {
        cliService.execute("vc template list").isSuccess shouldBe true
    }

    @Test
    fun listPolicies() {
        cliService.execute("vc policy list").isSuccess shouldBe true
    }

    @Test
    fun proposeCredential() {

        cliService.execute("wallet create --name Faber").isSuccess shouldBe true
        cliService.execute("wallet create --name Alice").isSuccess shouldBe true
        cliService.execute("agent start").isSuccess shouldBe true

        try {
            cliService.execute("protocol invitation connect --inviter=faber").isSuccess shouldBe true

            val subjectData = """
            {
                "givenName": "Alice",
                "familyName": "Garcia",
                "ssn": "123-45-6789",
                "degree": "Bachelor of Science, Marketing",
                "status": "graduated",
                "year": "2015",
                "average": "5"
            }""".trimJson()

            val command = "vc propose -t UniversityTranscript -i Faber.Did -s Alice.Did -d $subjectData"
            cliService.execute(command).isSuccess shouldBe true

        } finally {
            cliService.execute("agent stop").isSuccess shouldBe true
            cliService.execute("wallet remove Alice").isSuccess shouldBe true
            cliService.execute("wallet remove Faber").isSuccess shouldBe true
        }
    }

    @Test
    fun issueCredential() {

        cliService.execute("wallet create --name Faber").isSuccess shouldBe true
        cliService.execute("wallet create --name Alice").isSuccess shouldBe true
        cliService.execute("wallet create --name Acme").isSuccess shouldBe true
        cliService.execute("agent start").isSuccess shouldBe true

        val faber = modelService.findWalletByName("Faber") as Wallet

        try {

            cliService.execute("protocol invitation connect --inviter=Acme --invitee=Alice").isSuccess shouldBe true

            val faberDid = faber.createDid().uri

            cliService.execute("vc issue -t VerifiableId -i $faberDid -s Alice_Acme.myDid --out target/VerifiableId.json").isSuccess shouldBe true
            cliService.execute("vc present -h Alice_Acme.myDid -y Alice_Acme.theirDid -c 1234 --vc target/VerifiableId.json --out target/VerifiablePresentation.json").isSuccess shouldBe true

            val challengePolicy = """ChallengePolicy={"challenges":["1234"],"applyToVC":false}"""
            cliService.execute("vc verify -p SignaturePolicy -p $challengePolicy --vc target/VerifiablePresentation.json").isSuccess shouldBe true

        } finally {
            cliService.execute("agent stop").isSuccess shouldBe true
            cliService.execute("wallet remove Acme").isSuccess shouldBe true
            cliService.execute("wallet remove Alice").isSuccess shouldBe true
            cliService.execute("wallet remove Faber").isSuccess shouldBe true
        }
    }
}
