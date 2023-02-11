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

import org.didcommx.didcomm.message.Message
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset


// A mutable holder of a nullable type
// data class Holder<T>(var obj: T?)

/***********************************************************************************************************************
 * DateTime
 */

fun dateTimeNow(): OffsetDateTime {
    return OffsetDateTime.now(ZoneOffset.UTC)
}

fun dateTimeInstant(seconds: Long): OffsetDateTime {
    val instant = Instant.ofEpochSecond(seconds)
    return OffsetDateTime.ofInstant(instant, ZoneOffset.UTC)
}


/***********************************************************************************************************************
 * Map
 */

// [TODO] Better type magic?
fun Map<*, *>.toUnionMap(other: Map<*, *>): Map<*, *> {
    val unionMap = this.toMutableMap(); unionMap.putAll(other)
    return unionMap.toMap()
}

@Suppress("UNCHECKED_CAST")
fun Map<String, Any?>.toDeeplySortedMap(): Map<String, Any?> {
    val auxMap = this.toMutableMap()
    fun procList(lst: List<*>): List<*> = run {
        lst.map {
            when (val v = it) {
                is Map<*, *> -> (v as Map<String, Any?>).toDeeplySortedMap()
                is List<*> -> procList(v)
                else -> v
            }
        }
    }
    for ((k, v) in auxMap) {
        when (v) {
            is Map<*, *> -> auxMap[k] = (v as Map<String, Any?>).toDeeplySortedMap()
            is List<*> -> auxMap[k] = procList(v)
            else -> auxMap[k] = v
        }
    }
    // sort '@' -> '~' ...
    val comparator: Comparator<String> = Comparator { o1, o2 -> run {
            if (o1 != o2) {
                if (o1.startsWith('~')) "@$o1".compareTo(o2)
                else if (o2.startsWith('~')) o1.compareTo("@$o2")
                else o1.compareTo(o2)
            } else 0
        }
    }

    return LinkedHashMap(auxMap.toSortedMap(comparator)).toMap()
}

/***********************************************************************************************************************
 * Json
 */

fun String.selectJson(path: String): String? {
    val selected = this.decodeJson().selectJson(path)
    return if (selected == null || selected is String)
        selected as? String
    else
        gson.toJson(selected)
}

@Suppress("UNCHECKED_CAST")
fun Map<String, Any?>.selectJson(path: String): Any? {
    require(path.isNotEmpty()) { "Empty path" }
    val toks = path.split(".")
    val extKey = toks[0]
    val first = if (extKey.endsWith(']')) {
        val keyToks = extKey.split(Regex("""[\[\]]"""))
        val actKey = keyToks[0]
        val idx = keyToks[1].toInt()
        val lstVal = this[actKey] as List<String>
        lstVal[idx]
    } else {
        this[extKey]
    }
    if (first == null || toks.size == 1) {
        return first
    }
    if (first is Map<*, *>) {
        val next = first as Map<String, Any?>
        val tail = path.substring(extKey.length + 1)
        return next.selectJson(tail)
    }
    return null
}

/***********************************************************************************************************************
 * Message
 */

fun Message.shortString(): String {
    return "[id=$id, thid=$thid, type=$type]"
}

