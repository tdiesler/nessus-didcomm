package org.nessus.didcomm.util

import java.util.*

open class AttachmentKey<T>(val name: String, val type: Class<T>) {

    constructor(type: Class<T>) : this(type.name, type)

    override fun hashCode(): Int {
        return Objects.hash(name, type)
    }

    override fun equals(other: Any?): Boolean {
        if (this === other) return true
        if (other as? AttachmentKey<*> == null) return false
        return type == other.type && name == other.name
    }

    override fun toString(): String {
        val cname = type.name
        return "[name=$name, type=$cname]"
    }
}
