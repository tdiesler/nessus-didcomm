package org.nessus.didcomm.service

import id.walt.servicematrix.BaseService
import mu.KLogger
import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.util.AttachmentSupport
import org.nessus.didcomm.util.Attachments

abstract class AbstractAttachmentsService: BaseService(), Attachments {
    abstract val log: KLogger

    val attachments: Attachments = AttachmentSupport()

    override val attachmentKeys get() = attachments.attachmentKeys

    override fun <T : Any> putAttachment(key: AttachmentKey<T>, value: T?): T? {
        return attachments.putAttachment(key, value)
    }

    override fun putAllAttachments(source: Attachments) {
        return attachments.putAllAttachments(source)
    }

    override fun <T : Any> hasAttachment(key: AttachmentKey<T>): Boolean {
        return attachments.hasAttachment(key)
    }

    override fun <T : Any> getAttachment(key: AttachmentKey<T>): T? {
        return attachments.getAttachment(key)
    }

    override fun <T : Any> getAttachment(key: AttachmentKey<T>, defaultValue: T): T {
        return attachments.getAttachment(key, defaultValue)
    }

    override fun <T : Any> removeAttachment(key: AttachmentKey<T>): T? {
        return attachments.removeAttachment(key)
    }

}