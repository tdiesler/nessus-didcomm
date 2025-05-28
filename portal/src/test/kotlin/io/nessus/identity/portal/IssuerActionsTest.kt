package io.nessus.identity.portal

import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import kotlinx.serialization.json.jsonArray
import org.junit.jupiter.api.Test

class IssuerActionsTest {

    @Test
    fun issuerMetadata() {

        val metadataUrl = IssuerActions.issuerMetadataUrl
        metadataUrl.shouldEndWith("/issuer/.well-known/openid-credential-issuer")

        val jsonObj = IssuerActions.issuerMetadata.toJSON()
        jsonObj["credentials_supported"].shouldNotBeNull().jsonArray
    }
}