package org.nessus.didcomm.model

abstract class MessageType (

    /**
     * The header conveying the DIDComm Message Type URI.
     * REQUIRED
     */
    val type: String
) {
    companion object {
        const val OUT_OF_BAND_INVITATION = "https://didcomm.org/out-of-band/2.0/invitation"
    }
}
