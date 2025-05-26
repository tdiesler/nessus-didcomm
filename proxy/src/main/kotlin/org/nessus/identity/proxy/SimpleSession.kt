package org.nessus.identity.proxy

import com.typesafe.config.Config
import com.typesafe.config.ConfigFactory
import id.walt.oid4vc.responses.TokenResponse
import kotlinx.coroutines.CompletableDeferred

object SimpleSession {

    private val storage = mutableMapOf<String, Any>()

    fun getCredentialOfferContext(): CredentialOfferContext? {
        return storage["CredentialOfferContext"] as? CredentialOfferContext
    }

    fun setCredentialOfferContext(ctx: CredentialOfferContext) {
        storage["CredentialOfferContext"] = ctx
    }
}