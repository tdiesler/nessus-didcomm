package io.nessus.identity.portal

import java.net.URI
import java.net.URLDecoder

fun urlQueryToMap(url: String): Map<String, String> {
    return URI(url).rawQuery?.split("&")?.associate { p ->
        p.split("=", limit = 2).let { (k, v) -> k to URLDecoder.decode(v, "UTF-8") }
    } ?: mapOf()
}
