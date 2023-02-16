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
package org.nessus.didcomm.test.crypto

import id.walt.crypto.KeyAlgorithm
import id.walt.services.keystore.KeyType
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.nessus.didcomm.did.Did
import org.nessus.didcomm.did.DidMethod
import org.nessus.didcomm.protocol.RFC0019EncryptionEnvelope
import org.nessus.didcomm.protocol.RFC0023DidExchangeProtocolV1.Companion.RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V1
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.test.Alice
import org.nessus.didcomm.util.encodeJson
import org.nessus.didcomm.util.selectJson
import org.nessus.didcomm.util.trimJson

class RFC0019EnvelopeTest: AbstractAgentTest() {
    val log = KotlinLogging.logger {}

    @Test
    fun pack_unpack_envelope() {

        val faberDid = didService.createDid(DidMethod.KEY, KeyAlgorithm.EdDSA_Ed25519)
        val aliceDid = didService.createDid(DidMethod.KEY, KeyAlgorithm.EdDSA_Ed25519)

        // Delete the key from store (i.e. Alice's Did is external for pack)
        val aliceKey = keyStore.load(aliceDid.verkey, KeyType.PRIVATE)
        keyStore.delete(aliceDid.verkey)

        val rfc0019 = RFC0019EncryptionEnvelope()
        val envelope = rfc0019.packEncryptedEnvelope("Scheena Dog", faberDid, aliceDid)

        // Restore the key to store (i.e. Alice's Did is internal for unpack)
        keyStore.store(aliceKey)
        keyStore.addAlias(aliceKey.keyId, aliceDid.qualified)
        keyStore.addAlias(aliceKey.keyId, aliceDid.verkey)

        val message = rfc0019.unpackEncryptedEnvelope(envelope)?.message
        message shouldBe "Scheena Dog"
    }

    @Test
    fun unpack_pack_DidEx_Request() {

        val aliceDidSov = didService.createDid(DidMethod.SOV, KeyAlgorithm.EdDSA_Ed25519, Alice.seed.toByteArray())

        // This is an actual DidEx Request from AcaPy sent to Alice
        val envelope = """
        {
            "protected":"eyJlbmMiOiJ4Y2hhY2hhMjBwb2x5MTMwNV9pZXRmIiwidHlwIjoiSldNLzEuMCIsImFsZyI6IkF1dGhjcnlwdCIsInJlY2lwaWVudHMiOlt7ImVuY3J5cHRlZF9rZXkiOiJ1VHhPUEJIcm0yamlHNFZsOEFKR0loaGhFMDZCQXUyOGVtUFVLNnZsd1h3MnZjOUdCSlRBc092c29fWmRhQkhZIiwiaGVhZGVyIjp7ImtpZCI6IkVTcUgyWXVZUlJYTU1mZzVxUWgxQTIzbnpCYVV2QU1DRVhMdEJyMnVESGJZIiwiaXYiOiIyRVdqaG1yZkUwbTU4eHp3UEpYZldnUGl5LVg0QktTTCIsInNlbmRlciI6Ik1IMU4wNHM3bElocDhSRTZQRnkwMHQ1THBZQWdYY3hxMXNDWlFaelFUbWJUOVhyZU5MR3kyQmV1bmIyZF9oXzB4TGo0RWQ0b2NjT0QxZW5jb2h0azIzd3B4TUxKWng3UzZoUVg0eS1sa3Z2MzA5aDV3SGxUOVozWW5JUT0ifX1dfQ==",
            "iv":"48x9NGldXm6GaQWK",
            "ciphertext":"TdhY5nKZbO9EY43NeddeAllrsI8EOHKI7DnpPNYS1rzLrzsy8prkq2YMcKKn78i7A6FfYlUr7CfzmHk5ebDh07Yn0ihXm2Z3CNbndo083dNtpg7KZxXs8dxWd7afyK8bZ-Bo7Jjpcnkb7BIndfML0mNr8sK5NIq5PdmWnb52JvlnIs-ZZjox758VDDJWkzDDumCRo4hd5xWGh8oMVJdU4Z14KQJ5rkdBeaFyKtEY8vn4MaTf9gDDz9VPlKlofBt4Vs9lhPFsFpVd1nPrQxgwZyy22dQe5kXWgSsn8M0x7Gb51IpLdQaTqt7k98hxDNRFDaAHjh8Wo7JFxOnUTTez679f_EFOobMdcoSTp0nhZRH-_GSz1gFnFJtpSYZLq6Sql4uhPtfjDZnOV7OUch9YI_TWm1EeA0Cf2lUZvLETbTVtmRNLnjoH5thxBigKB37PAfIN0X_WllINICic9Ouj76se-LnS1Q3ptS98VGKMOTQiXdPdAnlPgzParqTlB1p8_xJP79yNo2ZzL-utRoodDRPI1gB_JoK236SNBqTECDeRIziHA3nZhf_lv1vpIBrgIt6HfwYLC3sAO3hVSOEZl2B_f5-SRRw__NBjqwMUDCB2V_nHDZ3Cej8Y6f8RuBAO6oRbUcGGF2vCXJMaXpEJHiiixrj9sX84XQ3iddH8dNsuUlxCQSxRRq-V2Y84_0WbzWevXiX_YhZuhkVtYhz1xtwclOTl2TFVWNOUrzuKE3BX0MW94M6uUGA5YQZ5x4euXvgv96DwXJsKnuq_H39vzg73b1fNnavlhcY26Ql4Ohq3tv8ewQ1oURMPgNllOwd9NWctkk55wQQLHGKR1XH3fsm5TzbRkucwXuBaSGgoLgaqyqJZxM8aTLLv7ZWzGJmxC0qOdV3WOb2oKzi3QlygR8MUKro5S1vXgc2upjOx6NDmBmC-WDYusdoSsu5C8gIBJ6DPUgRLyRQ4g4JKxe-PRf--jt5JJVXmFeAPB490hbgmtQ4Gj9pHvijJIbSCJfVrcbNewJx5MybWIG5sYWGGnea4crJFxSHuKqHS0JLS64lQSqDe5V_3u-hmZxnioRQFbxJsl0HH4gdOGssJHvyckTzSiXqVrN0Z_VkTQ-pNsVj6J20baEbVF5VOSBbz_3GilqAafiw1j-nPJx4qpVMhs79CYM01LlhpL1YPS8PQipdlXW-bYyg5WCebXIytJJOPJZPR2RfNeGMcLzJdBIttwSfQUwOYqy5cTUHdkp9DucOAZsl5bUAJVLhCdNIJK50BuReuPiCnsOeG3kV2S45ARZXKLopYbt-seODFHKNMlq0RFjggPcNhoJKbC86D8kEzn-DGsDaTtibzqhOZ6z-SlTq2G142hPHzt9_0MBbixohLxb-B90uuFgEftOPPl8gYDbVSRzgOEn-jKwoxJIUkxaIxVn2W3Lu-BCr8fkhAiaKD0ANRRViv5m4LOQxOklieU3sbVImu5ARYgFzdnBmVDiWuTmOCT3l-zBVT0l7yx-5MEvi2KvrVwNNUthy18kvEbCehkzDDIqhgfSEevcZmQcHBK8VIhUwKgjntP8EZQOK1rDLf_2z4YXdBz97tre3ZcqyJbxrd91qBWm60UyFgJ2_EaO2D9yAQn-hSnOD1MaguStWu1Hkgqvlm2wnZq1Ve9Wcs2PGH7JNu6QW3-mLhYoZOlmKzysKH44EXR2Bf02WT-NvObOdSdN4uSidfYptvMNffYlI2eH6Gw4WjVwQaZLJ5v3ux67pJsFW2DH1O8aCvHkZva5x2vWeMwCqdVD3pHCZCQ5Ga0uS11-AWLE6UHBQS-Y9wKXaYz2HlsrT6UtyKFVjlfGSBAVp4KktIQnTCRQdDmb0jdhTXzzAB0Yodh_l1aMUrKsgzmxXGTr6dpEpPkW4CRog-esW94FKWd9nwbjh8q49Dxi5yhy1FVTGggwKv0TbOvq0HyyK7YL7O-FVuyBYscJ4ulN8l2m7XKKopB7zWjdeFaSw2DAPFZCgm6pVLVTOtbqKz0xfCxseyMcKZ0BUhMMQ-EVWVOCipFmAfv9D4jinjhvn1zga1gEZUA7nE0F-dbG4qLZLZqEU4GQETNGC-w0PePwsFOV9H_2KspBtZyhqU9mhhGBovY7xSJ_eRJpXjLILC6KYR_qqdwJJD7qd70XgCPjCRFB-fRf1gegMQr2e7t08IqD82hP32QXPgkJUpcDIqRpO0V4Xa2lnHe2YbH7YNj-43gsiigjlXnkXvrGKKjh3gJHTDoMHv-tFxkAsd0uJOXgPqnB1V169CiOcSSTDBe6QlCl-ftMijyGSZkq-sy3pYfYjg3Y_cpkawjAbBs6AgwYC8cg==",
            "tag":"irHDyAi-pYUfNWXO1WH3qA=="
        }
        """.trimJson()

        val rfc0019 = RFC0019EncryptionEnvelope()
        val (message, _, recipientVerkey) = rfc0019.unpackEncryptedEnvelope(envelope)!!
        message.selectJson("@type") shouldBe RFC0023_DIDEXCHANGE_MESSAGE_TYPE_REQUEST_V1
        recipientVerkey shouldBe aliceDidSov.verkey


        val didDocAttachment = message.selectJson("did_doc~attach") as String
        val (didDocument, _) = diddocV1Service.extractDidDocAttachment(didDocAttachment, null)
        val didDocAttach = diddocV1Service.createDidDocAttachmentMap(didDocument, aliceDidSov) // This should be Faber's Did, but we don't have the secret

        val didRequest = """
        {
            "@type": "https://didcomm.org/didexchange/1.0/request",
            "@id": "7168055e-e19a-448c-9f4d-6e88d0de79c7",
            "~thread": {
                "thid": "7168055e-e19a-448c-9f4d-6e88d0de79c7",
                "pthid": "08e7ed44-6ed5-4aa8-9824-18dbeab5253d"
            },
            "did_doc~attach": ${didDocAttach.encodeJson()},
            "did": "CT7WXu41fw8A3s7wDy6VUp",
            "label": "Aries Cloud Agent"
        }
        """.trimJson()

        val faberVerkey = didDocument.publicKey[0].publicKeyBase58
        val faberDid = Did.fromSpec(didDocument.publicKey[0].controller, faberVerkey)
        log.info { "Faber Did: ${faberDid.qualified}" }

        rfc0019.packEncryptedEnvelope(didRequest, aliceDidSov, faberDid)
    }
}

