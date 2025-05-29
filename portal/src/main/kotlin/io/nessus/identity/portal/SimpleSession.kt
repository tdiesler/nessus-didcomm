package io.nessus.identity.portal

object SimpleSession {

    private val storage = mutableMapOf<String, Any>()

    fun getCredentialOfferContext(id: String) : CredentialOfferContext? {
        return storage["CredentialOfferContext"] as? CredentialOfferContext
    }

    fun putCredentialOfferContext(id: String, ctx: CredentialOfferContext) {
        storage["CredentialOfferContext"] = ctx
    }
}