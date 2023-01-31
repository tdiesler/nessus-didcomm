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
package org.nessus.didcomm.util

@Suppress("UNCHECKED_CAST")
open class AttachmentSupport : Attachments {

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
