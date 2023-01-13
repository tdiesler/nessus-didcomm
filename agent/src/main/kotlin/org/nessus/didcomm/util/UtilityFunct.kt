package org.nessus.didcomm.util


/***********************************************************************************************************************
 * Map
 */

fun Map<*, *>.toUnionMap(other: Map<*, *>): Map<*, *> {
    val unionMap = this.toMutableMap(); unionMap.putAll(other)
    return unionMap.toMap()
}


