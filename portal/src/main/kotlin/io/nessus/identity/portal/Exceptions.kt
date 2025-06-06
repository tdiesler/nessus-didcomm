package io.nessus.identity.portal

class VerificationException(val vcId: String, message: String) : RuntimeException(message)
