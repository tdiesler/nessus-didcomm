package org.nessus.didcomm.test.model.vc

import id.walt.credentials.w3c.VerifiableCredential
import io.kotest.matchers.shouldBe
import org.nessus.didcomm.model.DanubeTechVerifiableCredential
import org.nessus.didcomm.model.encodeJson
import org.nessus.didcomm.test.AbstractAgentTest
import org.nessus.didcomm.util.decodeJson

class VCSerializationTest: AbstractAgentTest() {

    @Test
    fun testSerialization() {
        for (path in listOf("/vc/passport.vc.json")) {
            val json = readResource(path)
            val expData = json.decodeJson()
            val vcDan = DanubeTechVerifiableCredential.fromJson(json)
            val vcW3C = VerifiableCredential.fromJson(json)

            vcDan.toJson().decodeJson() shouldBe expData
            vcW3C.toJson().decodeJson() shouldBe expData
            vcW3C.encodeJson(true).decodeJson() shouldBe expData
        }
    }
}