package io.nessus.identity.proxy

import io.github.oshai.kotlinlogging.KotlinLogging
import io.kotest.matchers.shouldBe
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.Test

class NessusOpenID4VCTest {

    private val log = KotlinLogging.logger {}

    @Test
    fun issuerMetadata() {
        runBlocking {
            val oid4vc = NessusOpenID4VC.buildFromConfig()
            val issuerUrl = "https://api-conformance.ebsi.eu/conformance/v3/issuer-mock"
            val metadata = oid4vc.resolveOpenIDProviderMetadata(issuerUrl)
            metadata.credentialIssuer shouldBe issuerUrl
        }
    }

    // Private ---------------------------------------------------------------------------------------------------------
}