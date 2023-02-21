/*-
 * #%L
 * Nessus DIDComm :: Agent
 * %%
 * Copyright (C) 2022 - 2023 Nessus
 * %%
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 * #L%
 */
package org.nessus.didcomm.service

import org.nessus.didcomm.util.AttachmentKey
import org.nessus.didcomm.util.AttachmentSupport
import org.nessus.didcomm.util.Attachments

abstract class AbstractAttachmentsService: AbstractBaseService(), Attachments {

    private val attachments: Attachments = AttachmentSupport()

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
