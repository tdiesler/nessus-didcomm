package org.nessus.didcomm.util

interface Attachments {
    /**
     * Get the set of available keys.
     */
    val attachmentKeys: Set<AttachmentKey<out Any>>

    /**
     * Attach an arbitrary object with this element.
     * @return The previous attachment object or null
     */
    fun <T: Any> putAttachment(key: AttachmentKey<T>, value: T?): T?

    /**
     * Copy all attachments from sourse to target.
     */
    fun putAllAttachments(source: Attachments)

    /**
     * True if there is an attached object for a given key
     */
    fun <T: Any> hasAttachment(key: AttachmentKey<T>): Boolean

    /**
     * Get the attached object for a given key
     * @return The attached object or null
     */
    fun <T: Any> getAttachment(key: AttachmentKey<T>): T?

    /**
     * If not attached already, create the attachment with the given default
     * @return The attached object
     */
    fun <T: Any> getAttachment(key: AttachmentKey<T>, defaultValue: T): T

    /**
     * Remove an attached object for a given key
     * @return The attached object or null
     */
    fun <T: Any> removeAttachment(key: AttachmentKey<T>): T?
}
