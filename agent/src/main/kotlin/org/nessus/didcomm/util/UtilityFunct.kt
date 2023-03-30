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

import org.didcommx.didcomm.message.Attachment
import org.didcommx.didcomm.message.Message
import java.net.URI
import java.time.Instant
import java.time.OffsetDateTime
import java.time.ZoneOffset


// A mutable holder of a nullable type
data class Holder<T>(var value: T? = null)

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
 * Map
 */

@Suppress("UNCHECKED_CAST")
fun Map<String, Any?>.unionMap(other: Map<String, Any?>): Map<String, Any?> {
    val unionMap = mutableMapOf<String, Any?>()
    for (k in this.keys + other.keys) {
        val thisVal = this[k]
        val otherVal = other[k]
        when {

            otherVal is String && otherVal.isNotEmpty() -> unionMap[k] = otherVal

            thisVal is String -> if (thisVal.isNotEmpty()) unionMap[k] = thisVal

            thisVal is List<*> && otherVal is List<*> -> when {
                thisVal.isNotEmpty() && otherVal.isEmpty() -> unionMap[k] = thisVal
                thisVal.isEmpty() && otherVal.isNotEmpty() -> unionMap[k] = otherVal
                thisVal[0] is Map<*, *> && otherVal[0] is Map<*, *> -> {
                    check(thisVal.size == otherVal.size) { "Arrays of map must have equal size: $thisVal vs. $otherVal" }
                    val unionList = mutableListOf<Map<String, Any?>>()
                    for (idx in (0 until thisVal.size)) {
                        val thisMap = thisVal[idx] as Map<String, Any?>
                        val otherMap = otherVal[idx] as Map<String, Any?>
                        unionList.add(thisMap.unionMap(otherMap))

                    }
                    unionMap[k] = unionList
                }
                else -> unionMap[k] = thisVal + otherVal
            }

            thisVal is Map<*, *> && otherVal is Map<*, *> -> {
                val thisMap = thisVal as Map<String, Any?>
                val otherMap = otherVal as Map<String, Any?>
                unionMap[k] = thisMap.unionMap(otherMap)
            }

            thisVal != null && otherVal == null -> unionMap[k] = thisVal
            thisVal == null && otherVal != null -> unionMap[k] = otherVal
        }
    }
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
 * Message
 */

@Suppress("UNCHECKED_CAST")
fun Attachment.Data.jsonData(): Map<String, Any>? {
    return toJSONObject()["json"] as? Map<String, Any>
}

fun Message.shortString(): String {
    return "[id=$id, thid=$thid, type=$type]"
}

/***********************************************************************************************************************
 * String
 */

fun String.ellipsis(n: Int = 8) = let { take(n) + "..." }

/***********************************************************************************************************************
 * URI
 */

fun URI.parameterMap(): Map<String, Any> {
    return rawQuery.split('&').associate {
        val toks = it.split('=')
        val name = toks.first()
        val value = toks.last()
        name to value
    }
}

