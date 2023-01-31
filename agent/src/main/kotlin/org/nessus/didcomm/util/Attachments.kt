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
