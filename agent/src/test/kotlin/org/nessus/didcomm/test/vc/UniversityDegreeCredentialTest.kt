package org.nessus.didcomm.test.vc

import id.walt.vclib.model.VerifiableCredential
import id.walt.vclib.schema.SchemaService
import io.kotest.matchers.shouldBe
import mu.KotlinLogging
import org.nessus.didcomm.test.AbstractAgentTest
import java.io.File

class UniversityDegreeCredentialTest: AbstractAgentTest() {
    private val log = KotlinLogging.logger {}

    @Test
    fun testUniversityDegreeValidSchema() {

        val metadata = UniversityDegree
        val vc = metadata.template!!.invoke()
        val vcEncoded = serializeCredential(vc)
        log.info { vcEncoded }

        generateSchema(UniversityDegree::class.java)
        val validationResult = SchemaService.validateSchema(vcEncoded)
        validationResult.errors?.forEach { e -> log.error {"Error: $e"} }
        validationResult.valid shouldBe true
    }

    private fun <T : VerifiableCredential> generateSchema(vc: Class<T>): String {
        return SchemaService.generateSchema(vc).also {
            log.info { "Generate Schema ${vc.simpleName}" }
            File("src/test/resources/w3c/schemas/${vc.simpleName}.json").writeText(it)
        }
    }

    private fun serializeCredential(vc: VerifiableCredential): String {
        return vc.encodePretty().also {
            log.info { "Serialize ${vc.javaClass.simpleName}" }
            File("src/test/resources/w3c/serialized/${vc.javaClass.simpleName}.json").writeText(it)
        }
    }
}
