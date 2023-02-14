package org.didcommx.didcomm.operations

import com.nimbusds.jose.JWSHeader
import com.nimbusds.jose.util.Base64URL
import com.nimbusds.jwt.JWTClaimsSet
import org.didcommx.didcomm.crypto.key.RecipientKeySelector
import org.didcommx.didcomm.crypto.key.SenderKeySelector
import org.didcommx.didcomm.crypto.signJwt
import org.didcommx.didcomm.crypto.verifyJwt
import org.didcommx.didcomm.exceptions.MalformedMessageException
import org.didcommx.didcomm.message.FromPrior
import org.didcommx.didcomm.message.Message

fun packFromPrior(
    message: Message,
    fromPriorIssuerKid: String?,
    keySelector: SenderKeySelector
): Pair<Message, String?> =
    message.fromPrior?.let {
        val key = keySelector.findSigningKey(fromPriorIssuerKid ?: it.iss)
        val updatedMessage = message.copy(
            fromPrior = null,
            fromPriorJwt = signJwt(JWTClaimsSet.parse(it.toJSONObject()), key)
        )
        Pair(updatedMessage, key.id)
    } ?: Pair(message, null)

fun unpackFromPrior(message: Message, keySelector: RecipientKeySelector): Pair<Message, String?> =
    message.fromPriorJwt?.let {
        val issKid = extractFromPriorKid(it)
        val key = keySelector.findVerificationKey(issKid)
        val updatedMessage = message.copy(
            fromPrior = FromPrior.parse(verifyJwt(it, key).toJSONObject()),
            fromPriorJwt = null
        )
        Pair(updatedMessage, key.id)
    } ?: Pair(message, null)

private fun extractFromPriorKid(fromPriorJwt: String): String {
    val segments = fromPriorJwt.split(".")
    if (segments.size != 3) {
        throw MalformedMessageException("JWT cannot be deserialized")
    }
    val jwsHeader = JWSHeader.parse(Base64URL(segments[0]))
    return jwsHeader.keyID
}
