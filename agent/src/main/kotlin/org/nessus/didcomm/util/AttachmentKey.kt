package org.nessus.didcomm.util

import java.util.*

class AttachmentKey<T>(val name: String, val type: Class<T>) {

    constructor(type: Class<T>) : this(type.name, type)

    override fun hashCode(): Int {
        return Objects.hash(name, type)
    }

    override fun equals(obj: Any?): Boolean {
        if (this === obj) return true
        if (obj == null) return false
        if (javaClass != obj.javaClass) return false
        val other = obj as AttachmentKey<*>
        return type == other.type && name == other.name
    }

    override fun toString(): String {
        val cname = type.name
        return "[name=$name,type=$cname]"
    }
}
