package io.nessus.identity.portal

import io.kotest.matchers.nulls.shouldNotBeNull
import io.kotest.matchers.string.shouldEndWith
import io.nessus.identity.service.Max
import org.junit.jupiter.api.Test

class AuthActionsTest : AbstractActionsTest() {

    @Test
    fun authMetadata() {
        
        val ctx = userLogin(Max)

        val metadataUrl = AuthActions.getAuthMetadataUrl(ctx)
        metadataUrl.shouldEndWith("/auth/${ctx.subjectId}/.well-known/openid-configuration")

        val jsonObj = AuthActions.getAuthMetadata(ctx)
        jsonObj.shouldNotBeNull()
    }
}