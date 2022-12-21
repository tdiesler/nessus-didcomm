package org.nessus.didcomm.model

import com.google.gson.Gson

/**
 * [Out of Band Invitation]https://identity.foundation/didcomm-messaging/spec/#out-of-band-messages
 *
 * {
 *   "type": "https://didcomm.org/out-of-band/2.0/invitation",
 *   "id": "<id used for context as pthid>",
 *   "from":"<sender's did>",
 *   "body": {
 *     "goal_code": "issue-vc",
 *     "goal": "To issue a Faber College Graduate credential",
 *     "accept": [
 *       "didcomm/v2",
 *       "didcomm/aip2;env=rfc587"
 *     ],
 *   },
 *   "attachments": [
 *     {
 *         "id": "request-0",
 *         "mime_type": "application/json",
 *         "data": {
 *             "json": "<json of protocol message>"
 *         }
 *     }
 *   ]
 * }
 */
data class OutOfBandInvitation(

    /**
     * Message ID. The id attribute value MUST be unique to the sender, across all messages they send.
     * This value MUST be used as the parent thread ID (pthid) for the response message that follows.
     * REQUIRED
     */
    val id: String,

    /**
     * The DID representing the sender to be used by recipients for future interactions.
     * REQUIRED
     */
    val from: String,

    /**
     * A self-attested code the receiver may want to display to the user or use in automatically deciding what to do with the out-of-band message.
     * OPTIONAL
     */
    val goalCode: String?,

    /**
     * A self-attested string that the receiver may want to display to the user about the context-specific goal of the out-of-band message.
     * OPTIONAL
     */
    val goal: String?,

    /**
     * An array of media types in the order of preference for sending a message to the endpoint.
     * These identify a profile of DIDComm Messaging that the endpoint supports.
     * OPTIONAL
     */
    val accept: List<String>?,

    /**
     * An array of attachments that will contain the invitation messages in order of preference that the receiver can use in responding to the message.
     * Each message in the array is a rough equivalent of the others, and all are in pursuit of the stated goal and goal_code.
     * Only one of the messages should be chosen and acted upon.
     * OPTIONAL
     */
    val attachments: List<Any>?,
) : MessageType(OUT_OF_BAND_INVITATION) {

    companion object {
        fun fromBody(body: Map<String, Any?>): OutOfBandInvitation {
            val gson = Gson()
            return gson.fromJson(gson.toJson(body), OutOfBandInvitation::class.java)
        }
    }
}
