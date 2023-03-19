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

import java.util.Objects
import kotlin.reflect.KClass

open class AttachmentKey<T: Any>(val name: String, val type: KClass<T>) {

    constructor(type: KClass<T>) : this(type.qualifiedName as String, type)

    override fun hashCode(): Int {
        return Objects.hash(name, type)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other as? AttachmentKey<*> == null) return false
        return type == other.type && name == other.name
    }

    override fun toString(): String {
        val cname = type.qualifiedName
        return "(name=$name, type=$cname)"
    }
}
