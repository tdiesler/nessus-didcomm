package org.nessus.identity.proxy

import io.github.oshai.kotlinlogging.KotlinLogging
import io.kotest.matchers.shouldBe
import io.ktor.client.HttpClient
import io.ktor.client.engine.cio.CIO
import io.ktor.serialization.kotlinx.json.json
import kotlinx.coroutines.isActive
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test

class OpenId4VCServiceTest {

    private val log = KotlinLogging.logger {}

    @Test
    fun issuerMetadata() {
        runBlocking {
            val issuerUrl = "https://api-conformance.ebsi.eu/conformance/v3/issuer-mock"
            val metadata = OpenId4VCService().resolveOpenIDProviderMetadata(issuerUrl)
            metadata.credentialIssuer shouldBe issuerUrl
        }
    }

    // Private ---------------------------------------------------------------------------------------------------------
}