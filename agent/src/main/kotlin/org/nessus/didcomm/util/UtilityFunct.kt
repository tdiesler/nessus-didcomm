package org.nessus.didcomm.util


// A mutable holder of a nullable type
data class Holder<T>(var obj: T?)

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
            if (o1 == o2) 0
            if (o1.startsWith('~')) "@$o1".compareTo(o2)
            else if (o2.startsWith('~')) o1.compareTo("@$o2")
            else o1.compareTo(o2)
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

