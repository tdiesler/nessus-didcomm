package io.nessus.identity.portal

object SimpleSession {

    private val storage = mutableMapOf<String, Any>()

    fun getCredentialOfferContext() : CredentialOfferContext? {
        return storage["CredentialOfferContext"] as? CredentialOfferContext
    }

    fun putCredentialOfferContext(ctx: CredentialOfferContext) {
        storage["CredentialOfferContext"] = ctx
    }
}