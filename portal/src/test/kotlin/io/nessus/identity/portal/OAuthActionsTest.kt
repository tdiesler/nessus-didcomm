package io.nessus.identity.portal

import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import kotlinx.serialization.json.jsonArray
import org.junit.jupiter.api.Test

class OAuthActionsTest {

    @Test
    fun oauthMetadata() {

        val metadataUrl = OAuthActions.oauthMetadataUrl
        metadataUrl.shouldEndWith("/oauth/.well-known/openid-configuration")

        val jsonObj = OAuthActions.oauthMetadata
        jsonObj.shouldNotBeNull()
    }
}