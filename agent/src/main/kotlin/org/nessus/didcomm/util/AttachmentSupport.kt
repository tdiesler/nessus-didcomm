package org.nessus.didcomm.util

@Suppress("UNCHECKED_CAST")
class AttachmentSupport : Attachments {

    private val attachments: MutableMap<AttachmentKey<out Any>, Any> = mutableMapOf()

    @get:Synchronized
    override val attachmentKeys: Set<AttachmentKey<out Any>>
        get() = attachments.keys

    @Synchronized
    override fun <T: Any> putAttachment(key: AttachmentKey<T>, value: T?): T? {
        return if (value != null)
            attachments.put(key, value) as T?
        else
            attachments.remove(key) as T?
    }

    @Synchronized
    override fun putAllAttachments(source: Attachments) {
        source.attachmentKeys.forEach { key ->
            attachments[key] = source.getAttachment(key)!!
        }
    }

    @Synchronized
    override fun <T: Any> getAttachment(key: AttachmentKey<T>): T? {
        return attachments[key] as T?
    }

    @Synchronized
    override fun <T: Any> getAttachment(key: AttachmentKey<T>, defaultValue: T): T {
        val value = getAttachment(key) ?: defaultValue
        putAttachment(key, value)
        return value
    }

    @Synchronized
    override fun <T: Any> hasAttachment(key: AttachmentKey<T>): Boolean {
        return attachments.containsKey(key)
    }

    @Synchronized
    override fun <T: Any> removeAttachment(key: AttachmentKey<T>): T? {
        return attachments.remove(key) as T?
    }
}
